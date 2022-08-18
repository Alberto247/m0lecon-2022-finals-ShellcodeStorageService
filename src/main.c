

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <linux/seccomp.h>  /* Definition of SECCOMP_* constants */
#include <sys/stat.h>
#include <linux/filter.h>   /* Definition of struct sock_fprog */
#include <linux/audit.h>    /* Definition of AUDIT_* constants */
#include <signal.h>   /* Definition of SIG* constants */
#include <sys/syscall.h>    /* Definition of SYS_* constants */
#include <sys/prctl.h>
#include <fcntl.h>
#include <stddef.h>
#include "sha256.h"

FILE* pwdfile;

static int install_syscall_filter_anon(void)
{
	struct sock_filter filter[] = {
        /* validate arch */
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, (offsetof(struct seccomp_data, arch))),
	    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
	    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL),
		/* Grab the system call number. */
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, nr))),
		/* List allowed syscalls. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_lseek, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_nanosleep, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 3), //IF NOT WRITE, BLOCK
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, args[0]))), //IF WRITE GET FIRST ARG
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 3, 1, 0), // IF GREATER OR EQUAL TO 3, BLOCK, ELSE ALLOW
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL)
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS)");
		exit(-1);
	}
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("prctl(SECCOMP)");
		exit(-1);
	}
	return 0;
}

void sha256(char* data, int size, char* hash){
    SHA256_CTX context;
    sha256_init(&context);
    sha256_update(&context, data, size);
    sha256_final(&context, hash);
}

static void handler(int sig, siginfo_t *si, void *unused)
{
    printf("Got SIGSEGV or SIGILL or SIGBUS or SIGFPE, looks like your shellcode is broken.");
    exit(-1);
}

void initialize(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void banner(){
    printf(" _______________________\n");
    printf("/                       \\\n");
    printf("|   _________________   |\n|  /   _____/\\_____  \\  |\n|  \\_____  \\   _(__  <  |\n| /_________//________/ |\n");
    printf("\\_______________________/\n");
}

void mainMenu(){
    puts("");
    puts("Welcome to S3 (Shellcode Storage Service)!");
    puts("1. Log In");
    puts("2. Register");
    puts("3. Test the service");
    puts("4. Exit");
    printf("> ");
}


void listFiles(){

}

void printFile(){

}

void saveFile(){

}

void runFile(){

}

void userMenu(int id){
        printf("Welcome to your private area user %d!\n", id);
        puts("1. List your shellcodes");
        puts("2. Print a shellcode");
        puts("3. Save a shellcode");
        puts("4. Execute a shellcode");
        puts("5. Exit");
        printf("> ");
}

void userHandler(int id){
    char choice;
    int n_shellcodes_running=0;
    while(1){
        userMenu(id);
        read(STDIN_FILENO, &choice, 1);
        getchar();
        if(choice=='5'){
            printf("Goodbye!");
            exit(0);
        }else if(choice=='1'){
            listFiles();
        }else if(choice=='2'){
            printFile();
        }else if(choice=='3'){
            saveFile();
        }else if(choice=='4'){
            if(n_shellcodes_running<5){
                n_shellcodes_running++;
                runFile();
            }else{
                puts("Sorry, only 5 shellcodes can be run at each login.");
            }
        }else{
            puts("Unknown option.");
        }
    }
}

void loginUser(){
    int id;
    printf("Please insert your ID: ");
    fscanf(stdin, "%d", &id);
    getchar();
    lseek(fileno(pwdfile), id<<5, SEEK_SET);
    printf("Please insert your password: ");
    char userpwd[64];
    char hash[32];
    fgets(userpwd, 63, stdin);
    userpwd[strcspn(userpwd, "\n")] = 0;
    sha256(userpwd, strlen(userpwd), hash); //hash password
    char correct_hash[32];
    read(fileno(pwdfile), correct_hash, 32);
    if(memcmp(hash, correct_hash, 32)==0){
       userHandler(id); 
    }else{
        puts("Wrong password!");
    }
}

void registerUser(){
    char userpwd[64];
    char hash[32];
    printf("Please insert your password: ");
    fgets(userpwd, 63, stdin);
    userpwd[strcspn(userpwd, "\n")] = 0;
    sha256(userpwd, strlen(userpwd), hash); //hash password
    struct flock f;
    f.l_type=F_WRLCK;
    f.l_whence=SEEK_END;
    f.l_start=0;
    f.l_len=32;
    if(fcntl(fileno(pwdfile), F_SETLKW, &f)){ //lock file from end 32 bytes
        perror("Cannot lock file");
        exit(-1);
    }
    struct stat s;
    lseek(fileno(pwdfile), 0, SEEK_END); //move to end
    fstat(fileno(pwdfile), &s); //get file size now
    int id = s.st_size >> 5; //calculate user's id
    write(fileno(pwdfile), hash, 32); //write pwd
    f.l_type=F_UNLCK;
    f.l_whence=SEEK_SET;
    f.l_start=s.st_size;
    f.l_len=32;
    if(fcntl(fileno(pwdfile), F_SETLKW, &f)){ //unlock file, use old size and not seek_end as size changes
        perror("Cannot unlock file");
        exit(-1);
    }
    printf("Your user's ID is: %d\n", id);
}

void anonymousShellcode(){
    void (*anonshell) (void) = NULL;
    unsigned char code[256] = {0};
    anonshell = mmap (0, 256, PROT_READ|PROT_WRITE|PROT_EXEC,
          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    puts("Send the bytes of your shellcode!");
    fgets(code, 255, stdin);
    memcpy(anonshell, code, 256);
    __builtin___clear_cache (anonshell, anonshell + sizeof(anonshell));
    if(!fork()){
        struct sigaction action;
        memset(&action, 0, sizeof(struct sigaction));
        action.sa_flags = SA_SIGINFO;
        action.sa_sigaction=handler;
        sigaction(SIGSEGV, &action, NULL);
        sigaction(SIGILL, &action, NULL);
        sigaction(SIGBUS, &action, NULL);
        sigaction(SIGFPE, &action, NULL);
        install_syscall_filter_anon();
        anonshell();
        exit(0);
    }
    sleep(5);
    puts("Your shellcode should have been run!");
}

int main(){
    initialize();
    banner();
    char choice;
    int anonShellcodeRunning=0;
    pwdfile = fopen("passwords", "a+");
    while(1){
        mainMenu();
        read(STDIN_FILENO, &choice, 1);
        getchar();
        if(choice=='4'){
            printf("Goodbye!");
            exit(0);
        }else if(choice=='1'){
            loginUser();
        }else if(choice=='2'){
            registerUser();
        }else if(choice=='3'){
            if(anonShellcodeRunning!=0){
                puts("Sorry, a shellcode has already been run.");
            }else{
                anonShellcodeRunning=1;
                anonymousShellcode();
            }
        }else{
            puts("Unknown option.");
        }
    }
}