//! cyberorch-deadline SECONDS -- COMMAND [ARGS...]
//!
//! Run COMMAND with a wall-clock deadline, as PID 1 of a tool container (D65-A).
//!
//! Exit status:
//!   the command's own code      it ended first (128 + N if it died of signal N)
//!   124                         the deadline passed first; the command's process group was killed
//!   125                         usage error
//!   127                         COMMAND could not be executed (a line saying so goes to stderr)
//!
//! As PID 1 it also reaps every orphan that is re-parented to it, and forwards the signals a
//! `docker stop` sends. When it exits, the container's PID namespace ends and takes every other
//! process with it, which is what makes the deadline hold against a tool that left its process
//! group. See docs/D65A_CONTAINER_DEADLINE_DESIGN.md.
use std::ffi::OsString;
use std::mem::MaybeUninit;
use std::os::unix::process::CommandExt;
use std::process::{exit, Command};
use std::time::{Duration, Instant};

const EXIT_DEADLINE: i32 = 124;
const EXIT_USAGE: i32 = 125;
const EXIT_NOT_EXECUTABLE: i32 = 127;
const MAX_SECONDS: u64 = 86_400;

/// Signals handed on to the command so that `docker stop` still reaches it.
const FORWARDED: [libc::c_int; 6] = [
    libc::SIGTERM,
    libc::SIGINT,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGUSR1,
    libc::SIGUSR2,
];

fn exit_code_of(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        128 + libc::WTERMSIG(status)
    }
}

fn usage(message: &str) -> ! {
    eprintln!("cyberorch-deadline: {message}");
    eprintln!("usage: cyberorch-deadline SECONDS -- COMMAND [ARGS...]");
    exit(EXIT_USAGE);
}

fn main() {
    let args: Vec<OsString> = std::env::args_os().collect();
    if args.len() < 4 || args[2] != "--" {
        usage("expected SECONDS -- COMMAND [ARGS...]");
    }
    let seconds: u64 = match args[1].to_str().and_then(|s| s.parse().ok()) {
        Some(n) if (1..=MAX_SECONDS).contains(&n) => n,
        _ => usage("SECONDS must be an integer from 1 to 86400"),
    };

    // Block the signals we handle *before* the command exists, so none can arrive between the
    // spawn and the first wait; they are then taken in order with sigtimedwait.
    let mut wanted: libc::sigset_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut inherited: libc::sigset_t = unsafe { MaybeUninit::zeroed().assume_init() };
    unsafe {
        libc::sigemptyset(&mut wanted);
        for signal in FORWARDED {
            libc::sigaddset(&mut wanted, signal);
        }
        libc::sigaddset(&mut wanted, libc::SIGCHLD);
        libc::sigprocmask(libc::SIG_BLOCK, &wanted, &mut inherited);
    }

    let started = Instant::now();
    let mut command = Command::new(&args[3]);
    command.args(&args[4..]);
    unsafe {
        // Its own process group, so the deadline can kill the whole tree with one call; and the
        // signal mask it would otherwise inherit from us put back.
        command.pre_exec(move || {
            libc::setpgid(0, 0);
            libc::sigprocmask(libc::SIG_SETMASK, &inherited, std::ptr::null_mut());
            Ok(())
        });
    }
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!(
                "cyberorch-deadline: cannot execute {}: {error}",
                args[3].to_string_lossy()
            );
            exit(EXIT_NOT_EXECUTABLE);
        }
    };
    let pid = child.id() as libc::pid_t;

    let deadline = Duration::from_secs(seconds);
    loop {
        let elapsed = started.elapsed();
        if elapsed >= deadline {
            break;
        }
        let left = deadline - elapsed;
        let timeout = libc::timespec {
            tv_sec: left.as_secs() as _,
            tv_nsec: left.subsec_nanos() as _,
        };
        let mut info: libc::siginfo_t = unsafe { MaybeUninit::zeroed().assume_init() };
        let signal = unsafe { libc::sigtimedwait(&wanted, &mut info, &timeout) };
        if signal < 0 {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EAGAIN) => break,
                Some(libc::EINTR) => continue,
                _ => exit(EXIT_USAGE),
            }
        }
        if signal == libc::SIGCHLD {
            // SIGCHLD does not queue: several children can end under one delivery, so reap until
            // nothing is left to reap. Orphans re-parented to PID 1 are reaped here too.
            loop {
                let mut status: libc::c_int = 0;
                let reaped = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
                if reaped <= 0 {
                    break;
                }
                if reaped == pid {
                    exit(exit_code_of(status));
                }
            }
            continue;
        }
        unsafe {
            libc::kill(pid, signal);
        }
    }

    eprintln!("cyberorch-deadline: expired after {seconds}s");
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    exit(EXIT_DEADLINE);
}
