use std::{fs::Permissions, os::unix::fs::PermissionsExt, path::Path, rc::Rc};

use nix::unistd::{chown, getpid, Gid, Uid};
use tokio::{
    io::AsyncWriteExt,
    net::{UnixListener, UnixStream},
    signal::unix::{signal, SignalKind},
    sync::mpsc,
    task,
};

use crate::{
    config::{Config, VtSelection},
    context::Context,
    error::Error,
    session::worker::TerminalMode,
    terminal::{self, Terminal},
};
use greetd_ipc::{
    codec::{Error as CodecError, TokioCodec},
    ErrorType, Request, Response,
};

/// Where a session asks for a hand-back. Anyone may connect: the peer's
/// user decides.
const HANDBACK_PATH: &str = "/run/greetd-handback.sock";

fn reset_vt(term_mode: &TerminalMode) -> Result<(), Error> {
    match term_mode {
        TerminalMode::Terminal { path, vt, .. } => {
            let term = Terminal::open(path)?;
            term.kd_setmode(terminal::KdMode::Text)?;
            term.vt_setactivate(*vt)?;
        }
        TerminalMode::Stdin | TerminalMode::Handover => (),
    }
    Ok(())
}

fn wait_vt(term_mode: &TerminalMode) -> Result<(), Error> {
    match term_mode {
        TerminalMode::Terminal { path, vt, .. } => {
            let term = Terminal::open(path)?;
            term.vt_waitactive(*vt)?;
        }
        TerminalMode::Stdin | TerminalMode::Handover => (),
    }
    Ok(())
}

fn wrap_result<T>(res: Result<T, Error>) -> Response {
    match res {
        Ok(_) => Response::Success,
        Err(Error::AuthError(msg)) => Response::Error {
            error_type: ErrorType::AuthError,
            description: msg,
        },
        Err(e) => Response::Error {
            error_type: ErrorType::Error,
            description: format!("{}", e),
        },
    }
}

async fn client_get_question(ctx: &Context) -> Response {
    match ctx.get_question().await {
        Ok(Some((auth_message_type, auth_message))) => Response::AuthMessage {
            auth_message_type,
            auth_message,
        },
        res => wrap_result(res),
    }
}

/// Retrieve the session's next question, unless the client cancels first.
/// The question can be a long time coming: a PAM module may wait by itself,
/// pam_fprintd for a finger, and a cancel must not have to wait with it.
async fn client_get_question_or_cancel(
    ctx: &Context,
    requests: &mut mpsc::Receiver<Request>,
    next: &mut Option<Request>,
) -> Response {
    tokio::select! {
        biased;
        resp = client_get_question(ctx) => resp,
        req = requests.recv() => match req {
            // A client that is gone has cancelled as well: nobody is left
            // to answer, and the wait would hold the context for its time.
            Some(Request::CancelSession) | None => {
                *next = Some(Request::CancelSession);
                Response::Error {
                    error_type: ErrorType::Error,
                    description: "cancelled".to_string(),
                }
            }
            req => {
                *next = req;
                client_get_question(ctx).await
            }
        },
    }
}

async fn client_handler(ctx: &Context, s: UnixStream) -> Result<(), Error> {
    let (mut rd, mut wr) = s.into_split();

    // Requests are read as they come, not as they are answered, so that a
    // cancel is seen while the answer to the request before it is awaited.
    // The reader is never dropped mid-read: reading a request is not
    // cancel-safe.
    // A few at most: a client that does not wait for answers waits here.
    let (tx, mut requests) = mpsc::channel(4);
    let reader = async move {
        loop {
            match Request::read_from(&mut rd).await {
                Ok(req) => {
                    if tx.send(req).await.is_err() {
                        return Ok(());
                    }
                }
                Err(CodecError::Eof) => return Ok(()),
                Err(e) => return Err(Error::from(e)),
            }
        }
    };

    let handler = async {
        let mut next = None;
        loop {
            let req = match next.take() {
                Some(req) => req,
                None => match requests.recv().await {
                    Some(req) => req,
                    None => return Ok::<(), Error>(()),
                },
            };

            let resp = match req {
                Request::CreateSession { username } => match ctx.create_session(username).await {
                    Ok(()) => client_get_question_or_cancel(ctx, &mut requests, &mut next).await,
                    res => wrap_result(res),
                },
                Request::PostAuthMessageResponse { response } => {
                    match ctx.post_response(response).await {
                        Ok(()) => {
                            client_get_question_or_cancel(ctx, &mut requests, &mut next).await
                        }
                        res => wrap_result(res),
                    }
                }
                Request::StartSession { cmd, env } => wrap_result(ctx.start(cmd, env).await),
                Request::CancelSession => wrap_result(ctx.cancel().await),
            };

            resp.write_to(&mut wr).await?;
        }
    };

    tokio::pin!(reader);
    tokio::pin!(handler);
    let read = tokio::select! {
        res = &mut handler => return res,
        res = &mut reader => res,
    };
    // The client is gone, or what it sent last could not be read: what it
    // had sent before is still handled, and no request is left half done.
    handler.await?;
    read
}

/// A session asks for a hand-back by connecting, and is told how it went.
async fn handback_handler(ctx: &Context, mut s: UnixStream) -> Result<(), Error> {
    let uid = s.peer_cred()?.uid();
    let answer: &[u8] = match ctx.hand_back(uid).await {
        Ok(()) => b"ok\n",
        Err(e) => {
            eprintln!("hand-back refused: {}", e);
            b"refused\n"
        }
    };
    s.write_all(answer).await?;
    Ok(())
}

// Return a TTY path and the TTY/VT number, based on the configured target.
//
// If the target is VtSelection::Current, return the path to the TTY
// referenced by stdin and the TTY number it is connected to if possible. If
// the referenced TTY is a PTY, fail. Otherwise, open tty0, get the current VT
// number, and return the path to that TTY and VT.
//
// If the target is VtSelection::Next, open tty0 and request the next VT
// number. Return the TTY and VT
//
// If the target is VtSelection::Specific, simply return the specified TTY and
// VT.
//
// If the target is VtSelection::None, return nothing.
fn get_tty(config: &Config) -> Result<TerminalMode, Error> {
    const TTY_PREFIX: &str = "/dev/tty";
    const PTS_PREFIX: &str = "/dev/pts";

    let term = match config.file.terminal.vt {
        VtSelection::Current => {
            let term = Terminal::stdin();
            match term.ttyname() {
                // We have a usable terminal, so let's decipher and return that
                Ok(term_name)
                    if term_name.starts_with(TTY_PREFIX) && term_name.len() > TTY_PREFIX.len() =>
                {
                    let vt = term_name[TTY_PREFIX.len()..]
                        .parse()
                        .map_err(|e| Error::Error(format!("unable to parse tty number: {}", e)))?;

                    TerminalMode::Terminal {
                        path: term_name,
                        vt,
                        switch: false,
                    }
                }
                Ok(term_name) if term_name.starts_with(PTS_PREFIX) => {
                    return Err("cannot use current VT when started from a psuedo terminal".into())
                }
                // We don't have a usable terminal, so we have to jump through some hoops
                _ => {
                    let sys_term = Terminal::open("/dev/tty0")
                        .map_err(|e| format!("unable to open terminal: {}", e))?;
                    let vt = sys_term
                        .vt_get_current()
                        .map_err(|e| format!("unable to get current VT: {}", e))?;
                    TerminalMode::Terminal {
                        path: format!("/dev/tty{}", vt),
                        vt,
                        switch: false,
                    }
                }
            }
        }
        VtSelection::Next => {
            let term = Terminal::open("/dev/tty0")
                .map_err(|e| format!("unable to open terminal: {}", e))?;
            let vt = term
                .vt_get_next()
                .map_err(|e| format!("unable to get next VT: {}", e))?;
            TerminalMode::Terminal {
                path: format!("/dev/tty{}", vt),
                vt,
                switch: config.file.terminal.switch,
            }
        }
        VtSelection::None => TerminalMode::Stdin,
        VtSelection::Specific(vt) => TerminalMode::Terminal {
            path: format!("/dev/tty{}", vt),
            vt,
            switch: config.file.terminal.switch,
        },
    };
    return Ok(term);
}

// Listener is a convenience wrapper for creating the UnixListener we need, and
// for providing cleanup on Drop.
struct Listener(UnixListener);

impl Listener {
    fn create(uid: Uid, gid: Gid) -> Result<(String, Listener), Error> {
        let path = format!("/run/greetd-{}.sock", getpid().as_raw());
        let _ = std::fs::remove_file(&path);
        let listener =
            UnixListener::bind(&path).map_err(|e| format!("unable to open listener: {}", e))?;
        chown(path.as_str(), Some(uid), Some(gid))
            .map_err(|e| format!("unable to chown greetd socket at {}: {}", path, e))?;
        Ok((path, Listener(listener)))
    }

    fn create_handback(path: &str) -> Result<Listener, Error> {
        let _ = std::fs::remove_file(path);
        let listener =
            UnixListener::bind(path).map_err(|e| format!("unable to open listener: {}", e))?;
        std::fs::set_permissions(path, Permissions::from_mode(0o666))
            .map_err(|e| format!("unable to open up socket at {}: {}", path, e))?;
        Ok(Listener(listener))
    }
}

/// The next connection, if there is a listener to have one.
async fn accept(listener: &Option<Listener>) -> std::io::Result<UnixStream> {
    match listener {
        Some(l) => l.0.accept().await.map(|(stream, _)| stream),
        None => std::future::pending().await,
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let addr = match self.0.local_addr() {
            Ok(addr) => addr,
            Err(_) => return,
        };
        if let Some(path) = addr.as_pathname() {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub async fn main(config: Config) -> Result<(), Error> {
    let service = if Path::new(&format!("/etc/pam.d/{}", config.file.general.service)).exists() {
        &config.file.general.service
    } else if Path::new(&format!("/usr/lib/pam.d/{}", config.file.general.service)).exists() {
        &config.file.general.service
    } else {
        return Err(format!("PAM '{}' service missing", config.file.general.service).into());
    };

    let greeter_service = if Path::new(&format!(
        "/etc/pam.d/{}",
        config.file.default_session.service
    ))
    .exists()
    {
        &config.file.default_session.service
    } else if Path::new(&format!(
        "/usr/lib/pam.d/{}",
        config.file.default_session.service
    ))
    .exists()
    {
        &config.file.default_session.service
    } else {
        service
    };

    let u = nix::unistd::User::from_name(&config.file.default_session.user)?.ok_or(format!(
        "configured default session user '{}' not found",
        &config.file.default_session.user
    ))?;

    let (listener_path, listener) = Listener::create(u.uid, u.gid)?;
    let handback = if config.file.terminal.handover {
        Some(Listener::create_handback(HANDBACK_PATH)?)
    } else {
        None
    };

    let term_mode = get_tty(&config)?;

    if !config.file.terminal.switch {
        wait_vt(&term_mode).map_err(|e| format!("unable to wait VT: {}", e))?;
    }

    let ctx = Rc::new(Context::new(
        config.file.default_session.command,
        config.file.default_session.user,
        greeter_service.to_string(),
        service.to_string(),
        term_mode.clone(),
        config.file.terminal.handover,
        config.file.general.source_profile,
        config.file.general.runfile,
        listener_path,
    ));

    if let (Some(s), true) = (config.file.initial_session, ctx.is_first_run()) {
        if let Err(e) = ctx.start_user_session(&s.user, vec![s.command]).await {
            eprintln!("unable to start greeter: {}", e);
            reset_vt(&term_mode).map_err(|e| format!("unable to reset VT: {}", e))?;

            std::process::exit(1);
        }
    } else if let Err(e) = ctx.greet().await {
        eprintln!("unable to start greeter: {}", e);
        reset_vt(&term_mode).map_err(|e| format!("unable to reset VT: {}", e))?;

        std::process::exit(1);
    }

    ctx.create_runfile();

    let mut alarm = signal(SignalKind::alarm()).expect("unable to listen for SIGALRM");
    let mut child = signal(SignalKind::child()).expect("unable to listen for SIGCHLD");
    let mut term = signal(SignalKind::terminate()).expect("unable to listen for SIGTERM");
    let mut int = signal(SignalKind::interrupt()).expect("unable to listen for SIGINT");

    loop {
        tokio::select! {
            _ = child.recv() => ctx.check_children().await.map_err(|e| format!("check_children: {}", e))?,
            _ = alarm.recv() => ctx.alarm().await.map_err(|e| format!("alarm: {}", e))?,
            _ = term.recv() => {
                ctx.terminate().await.map_err(|e| format!("terminate: {}", e))?;
                break;
            }
            _ = int.recv() => {
                ctx.terminate().await.map_err(|e| format!("terminate: {}", e))?;
                break;
            }
            stream = listener.0.accept() => match stream {
                Ok((stream, _)) => {
                    let client_ctx = ctx.clone();
                    task::spawn_local(async move {
                        if let Err(e) = client_handler(&client_ctx, stream).await {
                            client_ctx.cancel().await.expect("unable to cancel session");
                            eprintln!("client loop failed: {}", e);
                        }
                    });
                },
                Err(err) => return Err(format!("accept: {}", err).into()),
            },
            stream = accept(&handback) => match stream {
                Ok(stream) => {
                    let client_ctx = ctx.clone();
                    task::spawn_local(async move {
                        if let Err(e) = handback_handler(&client_ctx, stream).await {
                            eprintln!("hand-back failed: {}", e);
                        }
                    });
                },
                // Out of descriptors, say: still readable, and not worth
                // a busy loop or an exit.
                Err(err) => {
                    eprintln!("accept: {}", err);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[tokio::test]
    async fn handback_socket_is_open_to_all_and_replaced() {
        let dir = std::env::temp_dir().join(format!("greetd-test-{}", getpid()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("handback.sock");
        let path = path.to_str().unwrap();
        std::fs::write(path, "stale").unwrap();

        let listener = Listener::create_handback(path).unwrap();
        assert_eq!(std::fs::metadata(path).unwrap().mode() & 0o777, 0o666);
        let _client = UnixStream::connect(path).await.unwrap();
        let (stream, _) = listener.0.accept().await.unwrap();
        assert_eq!(
            stream.peer_cred().unwrap().uid(),
            nix::unistd::getuid().as_raw()
        );

        drop(listener);
        assert!(!Path::new(path).exists());
        std::fs::remove_dir(&dir).unwrap();
    }
}
