import os,signal,time
print('before',os.getpid(),flush=True)
os.kill(1,signal.SIGSTOP)
print('after',flush=True)
