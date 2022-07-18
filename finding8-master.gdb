set follow-fork-mode child
set substitute-path  /home/runner/work/tlspuffin/tlspuffin/target/x86_64-unknown-linux-gnu/release/build/wolfssl-sys-e95bba76f80a1b7e/out /home/max/projects/wolfssl
set env LD_LIBRARY_PATH /home/max/projects/wolfssl/src/.libs

break ssl.c:13777 if addSession.ticketLen > 255
break ssl.c:13791
break ssl.c:13809 if addSession.ticketLen > 255

break ssl.c:13974 if session.ticketLen > 255
break ssl.c:13974

c
