use std::{
    fs::File,
    path::Path,
    time::{Duration, Instant},
};

use nix::{
    sys::wait::{waitpid, WaitPidFlag, WaitStatus},
    unistd::alarm,
};
use tokio::{sync::RwLock, time::sleep};

use crate::{
    error::Error,
    scrambler::Scrambler,
    session::{
        interface::{Session, SessionChild, SessionState},
        worker::{AuthMessageType as SessAuthMessageType, SessionClass, TerminalMode},
    },
    terminal::Terminal,
};
use greetd_ipc::AuthMessageType;

struct SessionChildSet {
    child: SessionChild,
    time: Instant,
    is_greeter: bool,
}

struct SessionSet {
    session: Session,
    time: Instant,
}

struct ContextInner {
    current: Option<SessionChildSet>,
    scheduled: Option<SessionSet>,
    configuring: Option<SessionSet>,
    /// The greeter that handed over to `current`, or the session that handed
    /// back to the greeter in it, kept for a moment.
    outgoing: Option<SessionChildSet>,
}

/// How long a greeter is kept after it has handed over, in seconds: what it
/// last showed is on the display until the session's compositor takes it,
/// and would go with the greeter.
const HANDOVER_GRACE: u32 = 3;

/// How long a session is kept after it has handed back, in seconds. It is its
/// own to end, a few seconds in, and its teardown is cut short by a SIGTERM:
/// this is for one that does not end at all.
const HANDBACK_GRACE: u32 = 15;

impl SessionChildSet {
    /// How long this one is kept once it is outgoing.
    fn grace(&self) -> u32 {
        if self.is_greeter {
            HANDOVER_GRACE
        } else {
            HANDBACK_GRACE
        }
    }
}

/// Context keeps track of running sessions and start new ones.
pub struct Context {
    inner: RwLock<ContextInner>,
    greeter_bin: String,
    greeter_user: String,
    greeter_service: String,
    pam_service: String,
    term_mode: TerminalMode,
    /// Where an authenticated session goes: the greeter's VT, or with a
    /// hand-over one of its own.
    session_term_mode: TerminalMode,
    source_profile: bool,
    runfile: String,
    listener_path: String,
}

impl Context {
    pub fn new(
        greeter_bin: String,
        greeter_user: String,
        greeter_service: String,
        pam_service: String,
        term_mode: TerminalMode,
        handover: bool,
        source_profile: bool,
        runfile: String,
        listener_path: String,
    ) -> Context {
        // A hand-over needs VTs to hand over between.
        let session_term_mode = match (&term_mode, handover) {
            (TerminalMode::Terminal { .. }, true) => TerminalMode::Handover,
            _ => term_mode.clone(),
        };
        Context {
            inner: RwLock::new(ContextInner {
                current: None,
                scheduled: None,
                configuring: None,
                outgoing: None,
            }),
            greeter_bin,
            greeter_user,
            greeter_service,
            pam_service,
            term_mode,
            session_term_mode,
            source_profile,
            runfile,
            listener_path,
        }
    }

    /// Directly start an unauthenticated session, bypassing the normal
    /// scheduling. This function does not take the inner lock, and can thus
    /// be used while it is held.
    async fn start_unauthenticated_session(
        &self,
        class: SessionClass,
        user: &str,
        service: &str,
        cmd: Vec<String>,
    ) -> Result<SessionChild, Error> {
        self.prepare_unauthenticated_session(class, user, service, cmd, &self.term_mode)
            .await?
            .start()
            .await
    }

    /// An unauthenticated session up to its start, on the given terminal.
    async fn prepare_unauthenticated_session(
        &self,
        class: SessionClass,
        user: &str,
        service: &str,
        cmd: Vec<String>,
        term_mode: &TerminalMode,
    ) -> Result<Session, Error> {
        let mut scheduled_session = Session::new_external()?;
        scheduled_session
            .initiate(
                service,
                class,
                user,
                false,
                term_mode,
                self.source_profile,
                &self.listener_path,
            )
            .await?;
        loop {
            match scheduled_session.get_state().await {
                Ok(SessionState::Ready) => break,
                Ok(SessionState::Question(_, _)) => scheduled_session.post_response(None).await?,
                Err(err) => return Err(format!("session start failed: {}", err).into()),
            }
        }

        scheduled_session.send_args(cmd, vec![]).await?;
        Ok(scheduled_session)
    }

    /// Directly start a greeter session, bypassing the normal scheduling. This
    /// function does not take the inner lock, and can thus be used while it is
    /// held.
    async fn start_greeter(&self) -> Result<SessionChild, Error> {
        self.start_unauthenticated_session(
            SessionClass::Greeter,
            &self.greeter_user,
            &self.greeter_service,
            vec![self.greeter_bin.to_string()],
        )
        .await
    }

    /// Directly start a greeter session, bypassing the normal scheduling.
    pub async fn greet(&self) -> Result<(), Error> {
        {
            let inner = self.inner.read().await;
            if inner.current.is_some() {
                return Err("session already active".into());
            }
        }

        let mut inner = self.inner.write().await;
        inner.current = Some(SessionChildSet {
            child: self.start_greeter().await?,
            time: Instant::now(),
            is_greeter: true,
        });
        Ok(())
    }

    /// Check if this is the first time greetd starts since boot, or if it restarted for any reason
    pub fn is_first_run(&self) -> bool {
        !Path::new(&self.runfile).exists()
    }

    /// Create runfile used to check if greetd was already started since boot
    pub fn create_runfile(&self) {
        if let Err(err) = File::create(&self.runfile) {
            eprintln!("could not create runfile: {}", err);
        }
    }

    /// Directly start an initial session, bypassing the normal scheduling.
    pub async fn start_user_session(&self, user: &str, cmd: Vec<String>) -> Result<(), Error> {
        {
            let inner = self.inner.read().await;
            if inner.current.is_some() {
                return Err("session already active".into());
            }
        }

        let mut inner = self.inner.write().await;
        inner.current = Some(SessionChildSet {
            child: self
                .start_unauthenticated_session(SessionClass::User, user, &self.pam_service, cmd)
                .await?,
            time: Instant::now(),
            is_greeter: false,
        });
        Ok(())
    }

    /// Create a new session for configuration.
    pub async fn create_session(&self, username: String) -> Result<(), Error> {
        {
            let inner = self.inner.read().await;
            if inner.current.is_none() {
                return Err("session not active".into());
            }
            if inner.configuring.is_some() {
                return Err("a session is already being configured".into());
            }
            if inner.scheduled.is_some() {
                return Err("a session is already scheduled".into());
            }
            // The greeter is still up for a moment after a hand-over, and
            // has had its session: what it would start would replace it. A
            // session that handed back is no obstacle yet: the login can go
            // on while it ends, and only its start waits.
            if matches!(&inner.outgoing, Some(g) if g.is_greeter) {
                return Err("a session has already been handed over to".into());
            }
        }

        let mut session_set = SessionSet {
            session: Session::new_external()?,
            time: Instant::now(),
        };
        session_set
            .session
            .initiate(
                &self.pam_service,
                SessionClass::User,
                &username,
                true,
                &self.session_term_mode,
                self.source_profile,
                &self.listener_path,
            )
            .await?;

        let mut session = Some(session_set);
        let mut inner = self.inner.write().await;
        std::mem::swap(&mut session, &mut inner.configuring);
        drop(inner);

        // If there was a session under configuration, cancel it.
        if let Some(mut s) = session {
            s.session.cancel().await?;
        }

        Ok(())
    }

    /// Cancel the session being configured.
    pub async fn cancel(&self) -> Result<(), Error> {
        let mut inner = self.inner.write().await;
        if let Some(mut s) = inner.configuring.take() {
            s.session.cancel().await?;
        }
        Ok(())
    }

    /// Retrieve a question from the session under configuration.
    pub async fn get_question(&self) -> Result<Option<(AuthMessageType, String)>, Error> {
        let mut inner = self.inner.write().await;
        match &mut inner.configuring {
            Some(s) => match s.session.get_state().await? {
                SessionState::Ready => Ok(None),
                SessionState::Question(style, string) => Ok(Some((
                    match style {
                        SessAuthMessageType::Visible => AuthMessageType::Visible,
                        SessAuthMessageType::Secret => AuthMessageType::Secret,
                        SessAuthMessageType::Info => AuthMessageType::Info,
                        SessAuthMessageType::Error => AuthMessageType::Error,
                    },
                    string,
                ))),
            },
            None => Err("no session under configuration".into()),
        }
    }

    /// Answer a question to the session under configuration.
    pub async fn post_response(&self, answer: Option<String>) -> Result<(), Error> {
        let mut inner = self.inner.write().await;
        match &mut inner.configuring {
            Some(s) => match s.session.get_state().await? {
                SessionState::Ready => Err("session has no pending questions".into()),
                _ => s.session.post_response(answer).await,
            },
            None => {
                if let Some(mut answer) = answer {
                    answer.scramble();
                }
                return Err("no session under configuration".into());
            }
        }
    }

    /// Schedule the session under configuration with the provided arguments.
    pub async fn start(&self, cmd: Vec<String>, env: Vec<String>) -> Result<(), Error> {
        let mut session = self.inner.write().await.configuring.take();

        match &mut session {
            Some(s) => match s.session.get_state().await? {
                SessionState::Ready => {
                    // Send our arguments to the session.
                    s.session.send_args(cmd, env).await?;

                    if let TerminalMode::Handover = self.session_term_mode {
                        return self.hand_over(s).await;
                    }

                    let mut inner = self.inner.write().await;
                    std::mem::swap(&mut session, &mut inner.scheduled);
                    drop(inner);

                    // If there was a scheduled session, cancel it.
                    if let Some(mut p) = session {
                        p.session.cancel().await?;
                    }

                    // We give the greeter 5 seconds to prove itself well-behaved before
                    // we lose patience and shoot it in the back repeatedly. This is all
                    // handled by our alarm handler.
                    alarm::set(5);

                    Ok(())
                }
                SessionState::Question(..) => Err("session is not ready".into()),
            },
            None => Err("no session active".into()),
        }
    }

    /// Start the session on a VT of its own at once, with the greeter still
    /// up on its VT, and retire the greeter a moment later.
    async fn hand_over(&self, s: &mut SessionSet) -> Result<(), Error> {
        self.wait_for_session_handed_back().await?;

        let child = match s.session.start().await {
            Ok(child) => child,
            Err(e) => {
                // The worker may have switched VTs already: back to the
                // greeter's, which is still there to say what happened. One
                // that was killed left its VT in graphics mode.
                if let Some(vt) = s.session.vt() {
                    release_stuck_vt(vt);
                }
                // A greeter that came after a hand-back has a VT of its own.
                let greeter_vt = match &self.inner.read().await.current {
                    Some(g) => g.child.vt,
                    None => None,
                };
                match greeter_vt {
                    Some(vt) => request_vt(vt),
                    None => self.request_greeter_vt(),
                }
                return Err(format!("session start failed: {}", e).into());
            }
        };

        let mut inner = self.inner.write().await;
        // Two sessions started at once by the greeter: the first one stays,
        // and the greeter is not lost track of.
        if inner.outgoing.is_some() || !matches!(&inner.current, Some(g) if g.is_greeter) {
            child.term();
            return Err("a session has already been handed over to".into());
        }
        inner.outgoing = inner.current.take().map(|g| SessionChildSet {
            time: Instant::now(),
            ..g
        });
        inner.current = Some(SessionChildSet {
            child,
            time: Instant::now(),
            is_greeter: false,
        });
        alarm::set(HANDOVER_GRACE);
        Ok(())
    }

    /// The session that handed back is still ending, and the next one must
    /// not find it running. A killed one is gone in time.
    async fn wait_for_session_handed_back(&self) -> Result<(), Error> {
        let asked = Instant::now();
        loop {
            match &self.inner.read().await.outgoing {
                Some(g) if !g.is_greeter => {
                    if asked.elapsed() > Duration::from_secs(g.grace() as u64 + 10) {
                        return Err("the last session does not end".into());
                    }
                }
                _ => return Ok(()),
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    /// A hand-over the other way, for a logout, asked for by the user of the
    /// session in front: a greeter is started at once on the next free VT,
    /// with the session still up on its VT. The session's compositor is then
    /// not ended on the VT in front, where giving the display back to the
    /// console shows. Should the greeter not start, the session is switched
    /// back to, and nothing is lost; should it die later, the session is
    /// ended and another one started.
    pub async fn hand_back(&self, uid: u32) -> Result<(), Error> {
        if !matches!(self.session_term_mode, TerminalMode::Handover) {
            return Err("hand-overs are off".into());
        }

        // Held to the end. Anyone can ask: nobody queues for it, a greeter
        // waiting for a finger holds it for seconds.
        let mut inner = self.inner.try_write().map_err(|_| "greetd is busy")?;
        if inner.outgoing.is_some() {
            return Err("a hand-over is under way".into());
        }
        let session_vt = match &inner.current {
            Some(s) if !s.is_greeter && s.child.uid() == Some(uid) => s.child.vt,
            _ => return Err("not the session's user".into()),
        }
        .ok_or("the session has no VT of its own")?;
        let front = Terminal::open("/dev/tty0")?.vt_get_current()?;
        if front != session_vt {
            return Err("the session is not in front".into());
        }
        // No compositor holds it yet: the kernel would ignore the switch away,
        // and the greeter would wait for it for good, with the lock held.
        if Terminal::open(&format!("/dev/tty{}", session_vt))?.vt_is_auto()? {
            return Err("no compositor on the session's VT".into());
        }

        let mut greeter = self
            .prepare_unauthenticated_session(
                SessionClass::Greeter,
                &self.greeter_user,
                &self.greeter_service,
                vec![self.greeter_bin.to_string()],
                &TerminalMode::Handover,
            )
            .await?;
        let child = match greeter.start().await {
            Ok(child) => child,
            Err(e) => {
                if let Some(vt) = greeter.vt() {
                    release_stuck_vt(vt);
                }
                request_vt(session_vt);
                return Err(format!("greeter start failed: {}", e).into());
            }
        };

        inner.outgoing = inner.current.take().map(|s| SessionChildSet {
            time: Instant::now(),
            ..s
        });
        inner.current = Some(SessionChildSet {
            child,
            time: Instant::now(),
            is_greeter: true,
        });
        alarm::set(HANDBACK_GRACE);
        Ok(())
    }

    /// Ask for the greeter's VT, without waiting for it.
    fn request_greeter_vt(&self) {
        if let TerminalMode::Terminal { vt, .. } = &self.term_mode {
            request_vt(*vt);
        }
    }

    /// Start a greeter after a session. A hand-over left the greeter's VT,
    /// and a greeter that does not switch would not come back to it.
    async fn start_next_greeter(&self) -> Result<SessionChild, Error> {
        if let TerminalMode::Handover = self.session_term_mode {
            if let TerminalMode::Terminal { switch: false, .. } = self.term_mode {
                self.request_greeter_vt();
            }
        }
        self.start_greeter().await
    }

    /// Notify the Context of an alarm.
    pub async fn alarm(&self) -> Result<(), Error> {
        // Keep trying to terminate the greeter until it gives up.
        let mut inner = self.inner.write().await;

        // A greeter kept through a hand-over has had its time.
        if let Some(g) = &inner.outgoing {
            if g.time.elapsed() > Duration::from_secs(g.grace() as u64 + 5) {
                g.child.kill();
            } else {
                g.child.term();
            }
            alarm::set(1);
        }

        if let Some(mut p) = inner.scheduled.take() {
            if let Some(g) = inner.current.take() {
                if p.time.elapsed() > Duration::from_secs(10) {
                    // We're out of patience.
                    g.child.kill();
                } else {
                    // Let's try to give it a gentle nudge.
                    g.child.term();
                }
                inner.current = Some(g);
                inner.scheduled = Some(p);
                alarm::set(1);
                return Ok(());
            }
            drop(inner);
            let s = match p.session.start().await {
                Ok(s) => s,
                Err(e) => return Err(format!("session start failed: {}", e).into()),
            };
            let mut inner = self.inner.write().await;
            inner.current = Some(SessionChildSet {
                child: s,
                time: Instant::now(),
                is_greeter: false,
            });
        }

        Ok(())
    }

    /// Notify the Context that it needs to check its children for termination.
    /// This should be called on SIGCHLD.
    pub async fn check_children(&self) -> Result<(), Error> {
        loop {
            match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                // No scheduled exits.
                Ok(WaitStatus::StillAlive) => break Ok(()),

                // We got an exit, see if it's something we need to clean up.
                Ok(WaitStatus::Exited(pid, ..)) | Ok(WaitStatus::Signaled(pid, ..)) => {
                    let mut inner = self.inner.write().await;

                    // The greeter that handed over is gone, as it should.
                    if matches!(&inner.outgoing, Some(g) if g.child.owns_pid(pid)) {
                        // One that was killed left its VT in graphics mode.
                        if let Some(vt) = inner.outgoing.take().and_then(|g| g.child.vt) {
                            release_stuck_vt(vt);
                        }
                        if inner.current.is_none() && inner.scheduled.is_none() {
                            // So is the session it handed over to.
                            sleep(Duration::from_secs(1)).await;
                            inner.current = Some(SessionChildSet {
                                child: self.start_next_greeter().await?,
                                time: Instant::now(),
                                is_greeter: true,
                            });
                        }
                        continue;
                    }

                    let (was_greeter, sesion_length) = match &inner.current {
                        Some(s) if s.child.owns_pid(pid) => {
                            if let Some(vt) = s.child.vt {
                                release_stuck_vt(vt);
                            }
                            let res = (s.is_greeter, s.time.elapsed());
                            inner.current = None;
                            res
                        }
                        _ => continue,
                    };

                    match inner.scheduled.take() {
                        Some(mut scheduled) => {
                            // Our greeter finally bit the dust so we can
                            // start our scheduled session.
                            drop(inner);
                            let s = match scheduled.session.start().await {
                                Ok(s) => s,
                                Err(e) => return Err(format!("session start failed: {}", e).into()),
                            };
                            let mut inner = self.inner.write().await;
                            inner.current = Some(SessionChildSet {
                                child: s,
                                time: Instant::now(),
                                is_greeter: false,
                            });
                        }
                        None => {
                            if was_greeter && inner.outgoing.is_none() {
                                return Err("greeter exited without creating a session".into());
                            }
                            if let Some(g) = &inner.outgoing {
                                // The session ended while the greeter that
                                // handed over to it is still up, or the
                                // greeter a session handed back to while the
                                // session is: a new one is started once that
                                // one is gone. The alarm kills one that does
                                // not go.
                                g.child.term();
                                continue;
                            }
                            if sesion_length < Duration::from_secs(1) {
                                sleep(Duration::from_secs(1)).await;
                            }
                            inner.current = Some(SessionChildSet {
                                child: self.start_next_greeter().await?,
                                time: Instant::now(),
                                is_greeter: true,
                            });
                        }
                    }
                }

                // Useless status.
                Ok(_) => continue,

                // Interrupted.
                Err(nix::errno::Errno::EINTR) => continue,

                // We do not have any children right now.
                Err(nix::errno::Errno::ECHILD) => break Ok(()),

                // Uh, what?
                Err(e) => panic!("waitpid returned an unexpected error: {}", e),
            }
        }
    }

    /// Notify the Context that we want to terminate. This should be called on
    /// SIGTERM.
    pub async fn terminate(&self) -> Result<(), Error> {
        let mut inner = self.inner.write().await;
        if let Some(mut sess) = inner.configuring.take() {
            let _ = sess.session.cancel().await;
        }
        if let Some(mut sess) = inner.scheduled.take() {
            let _ = sess.session.cancel().await;
        }
        if let Some(sess) = inner.current.take() {
            sess.child.term();
        }
        if let Some(sess) = inner.outgoing.take() {
            sess.child.term();
        }
        Ok(())
    }
}

/// Ask for a VT, without waiting for it.
fn request_vt(vt: usize) {
    if let Ok(term) = Terminal::open(&format!("/dev/tty{}", vt)) {
        let _ = term.vt_request(vt);
    }
}

/// A session's worker that was killed did not put the session's VT back in
/// text mode. A VT in graphics mode with no process to ask for a switch
/// cannot be left: the kernel ignores every switch away from it, and the
/// next greeter would wait for its VT for good. Only the session's own VT,
/// and not one a compositor still holds.
fn release_stuck_vt(vt: usize) {
    if let Ok(term) = Terminal::open(&format!("/dev/tty{}", vt)) {
        if let Ok(true) = term.vt_is_auto() {
            let _ = term.kd_setmode(crate::terminal::KdMode::Text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(handover: bool) -> Context {
        Context::new(
            "greeter".to_string(),
            "greeter".to_string(),
            "greetd".to_string(),
            "greetd".to_string(),
            TerminalMode::Terminal {
                path: "/dev/tty1".to_string(),
                vt: 1,
                switch: true,
            },
            handover,
            false,
            "/nonexistent".to_string(),
            "/nonexistent".to_string(),
        )
    }

    #[tokio::test]
    async fn no_hand_back_without_a_session_or_hand_overs() {
        assert!(context(true).hand_back(1000).await.is_err());
        assert!(context(false).hand_back(1000).await.is_err());
    }
}
