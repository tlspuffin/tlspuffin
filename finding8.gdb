set follow-fork-mode child
set substitute-path  /home/runner/work/tlspuffin/tlspuffin/target/x86_64-unknown-linux-gnu/release/build/wolfssl-sys-e95bba76f80a1b7e/out /home/max/projects/wolfssl
set env LD_LIBRARY_PATH /home/max/projects/wolfssl/src/.libs

#break ssl.c:13587
#processing session ticket
#break internal.c:14286
#break ssl.c:13432


# write to session ticket
#break ssl.c:13536
# Write to cacheBuf
#break ssl.c:13501
# write to session ticket
#break ssl.c:13503
# Free cacheBuf
#break ssl.c:13557

break ssl.c:13501 if addSession.ticketLen > 255
break ssl.c:13485 if addSession.ticketLen > 255

# dupsession
break ssl.c:13518 if cacheTicBuff != 0 && *cacheTicBuff == '\0'
break ssl.c:13520 if cacheTicBuff != 0 && *cacheTicBuff == '\0'
#break ssl.c:13520

# inside sessiondup
#break ssl.c:19891 if *output.ticket == '\0'
#break ssl.c:19762
break ssl.c:19847


#break ssl.c:19859
#break ssl.c:19872
#break ssl.c:19879

#ClientSessionToSession
break ssl.c:13393
break ssl.c:13383
#break ssl.c:13400

# 13518 ssl.c
# 26939 internal.c
#watch *cacheTicBuff
#watch cacheSession->ticket

#run
c
