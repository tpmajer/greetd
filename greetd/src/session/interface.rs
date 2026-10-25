use std::{
    ffi::CString,
    os::unix::{
        io::{AsRawFd, FromRawFd},
        net::UnixDatagram,
    },
};

use nix::{
    fcntl::{fcntl, FcntlArg, FdFlag},
    sys::signal::Signal,
    unistd::{execv, fork, ForkResult, Pid},
};

use async_trait::async_trait;

use tokio::net::UnixDatagram as TokioUnixDatagram;

use super::worker::{
    AuthMessageType, ParentToSessionChild, SessionChildToParent, SessionClass, TerminalMode,
};
use crate::{error::Error, scrambler::Scrambler};

#[async_trait]
trait AsyncRecv<T: Sized> {
    async fn recv(sock: &mut TokioUnixDatagram) -> Result<T, Error>;
}

#[async_trait]
trait AsyncSend {
    async fn send(&self, sock: &mut TokioUnixDatagram) -> Result<(), Error>;
}

#[async_trait]
impl<'a> AsyncSend for ParentToSessionChild<'a> {
    async fn send(&self, sock: &mut TokioUnixDatagram) -> Result<(), Error> {
        let mut out =
            serde_json::to_vec(self).map_err(|e| format!("unable to serialize message: {}", e))?;
        sock.send(&out)
            .await
            .map_err(|e| format!("unable to send message: {}", e))?;
        out.scramble();
        Ok(())
    }
}

#[async_trait]
impl AsyncRecv<SessionChildToParent> for SessionChildToParent {
    async fn recv(sock: &mut TokioUnixDatagram) -> Result<SessionChildToParent, Error> {
        let mut data = [0; 10240];
        let len = sock
            .recv(&mut data[..])
            .await
            .map_err(|e| format!("unable to recieve message: {}", e))?;
        // The end of the socket: the worker has exited, or was killed.
        if len == 0 {
            return Err("the session worker is gone".into());
        }
        let msg = serde_json::from_slice(&data[..len])
            .map_err(|e| format!("unable to deserialize message: {}", e))?;
        Ok(msg)
    }
}

/// The sockets greetd and a session worker talk over. A pair of sequenced
/// packets, not of datagrams, which it is handled as: a datagram socket is
/// not told that its peer is gone, and a worker that died would be waited
/// for without end.
fn worker_pair() -> Result<(UnixDatagram, UnixDatagram), Error> {
    let mut fds = [0; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        return Err(format!(
            "could not create pipe: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    Ok(unsafe {
        (
            UnixDatagram::from_raw_fd(fds[0]),
            UnixDatagram::from_raw_fd(fds[1]),
        )
    })
}

/// SessionChild tracks the processes spawned by a session
pub struct SessionChild {
    pub task: Pid,
    pub sub_task: Pid,
    /// The VT of its own that a hand-over's session is on.
    pub vt: Option<usize>,
}

impl SessionChild {
    /// Check if this session has this pid.
    pub fn owns_pid(&self, pid: Pid) -> bool {
        self.task == pid
    }

    /// Send SIGTERM to the session child.
    pub fn term(&self) {
        let _ = nix::sys::signal::kill(self.sub_task, Signal::SIGTERM);
    }

    /// Send SIGKILL to the session child.
    pub fn kill(&self) {
        let _ = nix::sys::signal::kill(self.sub_task, Signal::SIGKILL);
        let _ = nix::sys::signal::kill(self.task, Signal::SIGKILL);
    }
}

#[derive(Debug)]
pub enum SessionState {
    Question(AuthMessageType, String),
    Ready,
}

/// A device to initiate a logged in PAM session.
pub struct Session {
    task: Pid,
    sock: TokioUnixDatagram,
    last_msg: Option<SessionChildToParent>,
    vt: Option<usize>,
}

impl Session {
    /// Create a session started as an external process.
    pub fn new_external() -> Result<Session, Error> {
        // Pipe used to communicate the true PID of the final child.
        let (parentfd, childfd) = worker_pair()?;

        let raw_child = childfd.as_raw_fd();
        let mut cur_flags = FdFlag::from_bits_retain(fcntl(raw_child, FcntlArg::F_GETFD)?);
        cur_flags.remove(FdFlag::FD_CLOEXEC);
        fcntl(raw_child, FcntlArg::F_SETFD(cur_flags))?;

        let cur_exe = std::env::current_exe()?;
        let bin = CString::new(cur_exe.to_str().expect("unable to get current exe name"))?;

        let child = match unsafe { fork() }.map_err(|e| format!("unable to fork: {}", e))? {
            ForkResult::Parent { child, .. } => child,
            ForkResult::Child => {
                execv(
                    &bin,
                    &[
                        &bin,
                        &CString::new("--session-worker").unwrap(),
                        &CString::new(format!("{}", raw_child as usize)).unwrap(),
                    ],
                )
                .expect("unable to exec");

                unreachable!("after exec");
            }
        };

        // tokio expects a non-blocking socket: on a blocking one a recv
        // made while it still takes the socket for readable blocks the
        // whole runtime until the worker's next message.
        parentfd.set_nonblocking(true)?;

        Ok(Session {
            task: child,
            sock: TokioUnixDatagram::from_std(parentfd)?,
            last_msg: None,
            vt: None,
        })
    }

    /// Initiates the session, which will cause authentication to begin.
    pub async fn initiate(
        &mut self,
        service: &str,
        class: SessionClass,
        user: &str,
        authenticate: bool,
        term_mode: &TerminalMode,
        source_profile: bool,
        listener_path: &str,
    ) -> Result<(), Error> {
        let msg = ParentToSessionChild::InitiateLogin {
            service: service,
            class: class,
            user: user,
            authenticate,
            tty: term_mode.clone(),
            source_profile,
            listener_path: listener_path,
        };
        msg.send(&mut self.sock).await?;
        Ok(())
    }

    /// Return the current state of this session.
    pub async fn get_state(&mut self) -> Result<SessionState, Error> {
        let msg = match self.last_msg.take() {
            Some(msg) => msg,
            None => SessionChildToParent::recv(&mut self.sock).await?,
        };

        self.last_msg = Some(msg.clone());

        match msg {
            SessionChildToParent::PamMessage { style, msg } => {
                Ok(SessionState::Question(style, msg))
            }
            SessionChildToParent::Success => Ok(SessionState::Ready),
            SessionChildToParent::Error(e) => Err(e),
            msg => panic!(
                "expected PamMessage, Success or Error from session worker, got: {:?}",
                msg
            ),
        }
    }

    /// Cancel the session.
    pub async fn cancel(&mut self) -> Result<(), Error> {
        self.last_msg = None;
        // A worker that is gone, after a failed authentication for one, has
        // nothing left to cancel: that is not an error.
        let sent = ParentToSessionChild::Cancel.send(&mut self.sock).await;
        // The worker only reads Cancel between PAM's questions, so a module
        // that waits, such as a fingerprint reader's, would hold it until
        // its timeout. A session that has not been started has nothing to
        // tear down, so end the worker instead. Only one that took the
        // message: the PID of one that is gone may be another process's.
        if sent.is_ok() {
            let _ = nix::sys::signal::kill(self.task, Signal::SIGTERM);
        }
        Ok(())
    }

    /// Send a response to an authentication question, or None to cancel the
    /// authentication attempt.
    pub async fn post_response(&mut self, answer: Option<String>) -> Result<(), Error> {
        self.last_msg = None;
        let r = ParentToSessionChild::PamResponse { resp: answer };
        r.send(&mut self.sock).await?;
        if let ParentToSessionChild::PamResponse {
            resp: Some(mut resp),
        } = r
        {
            resp.scramble();
        }
        Ok(())
    }

    ///
    /// Send the arguments that will be used to start the session.
    ///
    pub async fn send_args(&mut self, cmd: Vec<String>, env: Vec<String>) -> Result<(), Error> {
        let msg = ParentToSessionChild::Args { env, cmd };
        msg.send(&mut self.sock).await?;

        let msg = SessionChildToParent::recv(&mut self.sock).await?;

        self.last_msg = Some(msg.clone());

        match msg {
            SessionChildToParent::Success => Ok(()),
            SessionChildToParent::Error(e) => Err(e),
            msg => panic!(
                "expected Success or Error from session worker, got: {:?}",
                msg
            ),
        }
    }

    ///
    /// Start the session.
    ///
    pub async fn start(&mut self) -> Result<SessionChild, Error> {
        let msg = ParentToSessionChild::Start;
        msg.send(&mut self.sock).await?;

        let sub_task = loop {
            match SessionChildToParent::recv(&mut self.sock).await? {
                SessionChildToParent::Error(e) => return Err(e),
                SessionChildToParent::FinalChildPid(raw_pid) => {
                    break Pid::from_raw(raw_pid as i32)
                }
                SessionChildToParent::HandoverVt(vt) => {
                    self.vt = Some(vt as usize);
                    continue;
                }
                SessionChildToParent::PamMessage { .. } => {
                    // pam_conv after start, ignore
                    ParentToSessionChild::PamResponse { resp: None }
                        .send(&mut self.sock)
                        .await?;
                    continue;
                }
                msg => panic!(
                    "expected Error or FinalChildPid from session worker, got: {:?}",
                    msg
                ),
            };
        };

        self.sock.shutdown(std::net::Shutdown::Both)?;

        Ok(SessionChild {
            task: self.task,
            sub_task,
            vt: self.vt,
        })
    }

    /// The VT a hand-over's session was given, if it got as far, for one
    /// whose start failed too.
    pub fn vt(&self) -> Option<usize> {
        self.vt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn worker_messages_arrive_whole() {
        let (parent, child) = worker_pair().unwrap();
        parent.set_nonblocking(true).unwrap();
        let mut parent = TokioUnixDatagram::from_std(parent).unwrap();

        SessionChildToParent::Success.send(&child).unwrap();
        SessionChildToParent::FinalChildPid(7).send(&child).unwrap();
        assert!(matches!(
            SessionChildToParent::recv(&mut parent).await,
            Ok(SessionChildToParent::Success)
        ));
        assert!(matches!(
            SessionChildToParent::recv(&mut parent).await,
            Ok(SessionChildToParent::FinalChildPid(7))
        ));

        ParentToSessionChild::Start.send(&mut parent).await.unwrap();
        let mut data = [0; 10240];
        assert!(matches!(
            ParentToSessionChild::recv(&child, &mut data),
            Ok(ParentToSessionChild::Start)
        ));
    }

    #[tokio::test]
    async fn a_worker_that_is_gone_is_an_error() {
        let (parent, child) = worker_pair().unwrap();
        parent.set_nonblocking(true).unwrap();
        let mut parent = TokioUnixDatagram::from_std(parent).unwrap();

        // What it sent before it went is still read.
        SessionChildToParent::Success.send(&child).unwrap();
        drop(child);
        assert!(matches!(
            SessionChildToParent::recv(&mut parent).await,
            Ok(SessionChildToParent::Success)
        ));
        assert!(SessionChildToParent::recv(&mut parent).await.is_err());
        assert!(ParentToSessionChild::Cancel.send(&mut parent).await.is_err());
    }

    #[tokio::test]
    async fn greetd_gone_ends_the_worker() {
        let (parent, child) = worker_pair().unwrap();
        drop(parent);
        let mut data = [0; 10240];
        assert!(ParentToSessionChild::recv(&child, &mut data).is_err());
    }
}
