/*
 * HOOKS FEST! \o/
 */

#define __EXTERN_HOOK_TABLE__

#ifndef nr_syscalls
#define nr_syscalls 332
#endif

/* define this if you want (very) verbose kern logs */
#define __DEBUG__

#ifdef __DEBUG__
    #define DEBUGLOG(a) printk a
#else
    #define DEBUGLOG(a) ""
#endif

// Sebek's original includes
// from syscall.h
#include <linux/sched.h>
#include <linux/irq.h>

#include <linux/syscalls.h>

#include <asm/unistd.h>
#include <asm/desc.h>

#include "net.h"
#include "filter.h"

// from ...


// Missing includes...
#include <linux/fdtable.h>

// End Sebek's includes


// Sebek's original vars
// from syscall.c
//u32 BLOCK[BS];
/*
u32 tx_bytes;
u32 tx_packets;
u32 s_bytes;
u32 s_packets;

struct net_device *output_dev;
get_info_t * old_get_info;
*/
//----- these 2 pups used to track use of syscalls
atomic_t refcount = ATOMIC_INIT(0);
wait_queue_head_t wait;

// End Sebek's vars

unsigned int sys_table_global = 0;  // Address of syscalls table (global var)
void *hook_table[nr_syscalls];


asmlinkage static int hook_open(const char *pathname, int flags, int mode);

asmlinkage static ssize_t hook_read (unsigned int fd, char *buf, size_t count);
asmlinkage static ssize_t hook_readv (unsigned int fd, const struct iovec * vector , size_t count);
asmlinkage static ssize_t hook_read64 (unsigned int fd, char *buf, size_t count, off_t offset);
 
asmlinkage static ssize_t hook_write (unsigned int fd, const char *buf, size_t count);
asmlinkage static ssize_t hook_writev (unsigned int fd, const struct iovec * vector , size_t count);
asmlinkage static ssize_t hook_write64 (unsigned int fd, const char *buf, size_t count, off_t offset);

asmlinkage static int hook_fork (struct pt_regs regs);
asmlinkage static int hook_vfork (struct pt_regs regs);
asmlinkage static int hook_clone (struct pt_regs regs);

asmlinkage static long hook_socket (int call,unsigned long __user *args);


static void __init_hook_table(void)
{

    int i;

    /* clear table */
    for (i = 0; i < nr_syscalls; i ++)
        hook_table[i] = NULL;

    /* init hooks */
    hook_table[__NR_open]           = (void *)hook_open;
    hook_table[__NR_read]           = (void *)hook_read;
    hook_table[__NR_readv]          = (void *)hook_readv;
    hook_table[__NR_pread64]        = (void *)hook_read64;
    hook_table[__NR_write]          = (void *)hook_write;
    hook_table[__NR_writev]         = (void *)hook_writev;
    hook_table[__NR_pwrite64]       = (void *)hook_write64;
    hook_table[__NR_fork]           = (void *)hook_fork;
    hook_table[__NR_vfork]          = (void *)hook_vfork;
    hook_table[__NR_clone]          = (void *)hook_clone;
    hook_table[__NR_socketcall]     = (void *)hook_socket;

    /* (example hook) */
    //hook_table[__NR_exit]         = (void *)hook_example_exit;
    
    /* any additional (non-syscall) hooks go here */
    
    parse_params();
}

/* main hook uninit */
static void __uninit_hook_table(void)
{
    /* unload any additional non-syscall hooks here */

    /* un-do Daniel's tcp hook */
    //tcp = proc_net->subdir->next;

    /*  tcp4_seq_show() with original */
    //while (strcmp(tcp->name, "tcp") && (tcp != proc_net->subdir))
    //    tcp = tcp->next;

    //if (tcp != proc_net->subdir)
    //    ((struct tcp_seq_afinfo *)(tcp->data))->seq_show = original_tcp4_seq_show;
}

//
//
//		==== HOOKerS BELOW ====
//
//

/*
 * OPEN HOOK
 *
 */

asmlinkage
static int hook_open(const char __user *pathname, int flags, int mode)
{
    void **sys_p = (void **)sys_table_global;
    asmlinkage int (*original_sys_open)(const char *pathname, int flags, int mode) = sys_p[__NR_open];
    
    long retval;
    unsigned long inode;

    int pathmax;
    int len;
    char * buffer;
    char * path;
    int action;

    atomic_inc(&refcount);
    
    DEBUGLOG(("hook_open()!\n"));

    retval = original_sys_open(pathname, flags, mode);
    
    if (retval >= 0)
    { //------ open call worked
      //--mark for filtering always!!
      sbk_filter_open(fcheck_files(current->files,retval));

      DEBUGLOG((KERN_ALERT "Sebek - about to eval filt\n"));
      
      action = sbk_filter_eval(retval);
      
      DEBUGLOG((KERN_ALERT "Sebek - filter eval done\n"));
      
      //----- no action needed
      if(action == SBK_FILT_ACT_IGNORE) goto OUT;
      //----- no action needed if we are KSO and it doesnt look like keystrokes
      // if(action == SBK_FILT_ACT_KSO  && r > 1)goto OUT;
      
      //----- figure out our pathname max.    
      pathmax = BUFLEN - sizeof(struct sbk_h);
      buffer = kmalloc(pathmax,GFP_KERNEL);

      if (!buffer) goto OUT;

      //------ get inode;
      inode = fd2inode(retval);
 
      //----- get full pathname that corresponds to the inode
      path = fd2path(retval,buffer,pathmax);

      //----- get the the real length of the path, if its too big, truncate.
      len = strlen(path);
      if(len > pathmax)len = pathmax;

      sbk_log(SBK_OPEN,retval,inode,len,(const u_char *)path,0);

      kfree(buffer);
    }

    OUT:

    if(atomic_dec_and_test(&refcount))
       wake_up_interruptible(&wait);

  return retval;
}

/*
 * READ HOOKS
 *
 */

//----- nrd:  New Read, this calls the old read call then records all the
//-----       interesting data.  It uses the log function for recording.
asmlinkage static ssize_t hook_read (unsigned int fd, char *buf, size_t count) {

  void **sys_p = (void **)sys_table_global;
  asmlinkage int (*original_sys_read)(unsigned int fd, char *buf, size_t count) = sys_p[__NR_read];

  ssize_t r;
  char * ptr;
  int action;

  u_int32_t bufsize;
  u_int32_t inode;

  atomic_inc(&refcount);

  //----- run original sys_read....
  r = original_sys_read(fd, buf, count);


  //----- check for error and interest
  if(r < 1 || ((BLOCK[KSO_OFFSET] & 0x00000001) && r > 1))goto OUT;

  
  //--Filter Code Follows
  //--Determine action
  //printk(KERN_ALERT "Sebek - about to eval filt\n");
  action=sbk_filter_eval(fd);
  //printk(KERN_ALERT "Sebek - filter eval done\n");
  //----- no action needed
  if(action == SBK_FILT_ACT_IGNORE) goto OUT;
  //----- no action needed if we are KSO and it doesnt look like keystrokes
  if(action == SBK_FILT_ACT_KSO  && r > 1)goto OUT;



  //----- log the read contents.  Including context data.    
  bufsize = BUFLEN - sizeof(struct sbk_h);

  
  //----- get inode , eventually this will drive filtering.
  inode = fd2inode(fd);

  if(r < bufsize){

    //----- data is less than buffer size, we can copy it in single step
    sbk_log(SBK_READ,fd,inode,r,buf,1);
    
  }else{

    //----- data is > buffer size, need to nibble at it
    for(ptr = buf; ptr + bufsize  <= buf + r ; ptr+= bufsize){
      sbk_log(SBK_READ,fd,inode,bufsize,ptr,1);
    }

    //----- dont forget the remainder
    sbk_log(SBK_READ,fd,inode,r % bufsize,ptr,1);
  }
  

 OUT:

  if(atomic_dec_and_test(&refcount))
     wake_up_interruptible(&wait);

  return r;  
}

//----- nrdv:  New Readv, this calls the old readv call then records all the
//-----       interesting data.  It uses the log function for recording.
asmlinkage static ssize_t hook_readv (unsigned int fd, const struct iovec * vector , size_t count) {

  void **sys_p = (void **)sys_table_global;
  asmlinkage int (*original_sys_readv)(unsigned int fd, const struct iovec * vector , size_t count) = sys_p[__NR_readv];

  ssize_t r;
  ssize_t len;
  size_t  i;
  void * ptr;
  u_int32_t bufsize;
  u_int32_t inode;
  struct iovec * iov;
  int action;

  atomic_inc(&refcount);
 
  //----- run original sys_read....
  r = original_sys_readv(fd, vector, count);
 
  //----- check for error and interest
  if(r < 1 || ((BLOCK[KSO_OFFSET] & 0x00000001) && r > 1) ||  (count > UIO_MAXIOV))goto OUT;

  //--Filter Code Follows
  //--Determine action
  action=sbk_filter_eval(fd);
  //----- no action needed
  if(action == SBK_FILT_ACT_IGNORE) goto OUT;
  //----- no action needed if we are KSO and it doesnt look like keystrokes
  if(action == SBK_FILT_ACT_KSO  && r > 1)goto OUT;


 
  //----- allocate iovec buffer
  iov = kmalloc(count*sizeof(struct iovec), GFP_KERNEL);
  if (!iov)goto OUT;


  //----- copy over iovec struct
  if (copy_from_user(iov, vector, count*sizeof(*vector)))goto OUT_W_FREE;


  //----- log the read contents.  Including context data.    
  bufsize = BUFLEN - sizeof(struct sbk_h);

  //----- get inode , eventually this will drive filtering.
  inode = fd2inode(fd);


  for(i = 0; i < count; i++){
    len = iov[i].iov_len;
    
    if(len < bufsize){
      
      //----- data is less than buffer size, we can copy it in single step
      sbk_log(SBK_READ,fd,inode,r,iov[i].iov_base,1);
      
    }else{
      
      //----- data is > buffer size, need to nibble at it
      for(ptr = iov[i].iov_base; ptr + bufsize  <= iov[i].iov_base + r ; ptr+= bufsize){
	sbk_log(SBK_READ,fd,inode,bufsize,ptr,1);
      }
      
      //----- dont forget the remainder
      sbk_log(SBK_READ,fd,inode,r % bufsize,ptr,1);
    }
  }

 OUT_W_FREE:
  kfree(iov);

 OUT:

  if(atomic_dec_and_test(&refcount))
     wake_up_interruptible(&wait);
  
  return r;  
}


//----- nprd:  New Read, this calls the old pread call then records all the
//-----       interesting data.  It uses the log function for recording.
asmlinkage static ssize_t hook_read64 (unsigned int fd, char *buf, size_t count, off_t offset) {

  void **sys_p = (void **)sys_table_global;
  asmlinkage int (*original_sys_read64)(unsigned int fd, char *buf, size_t count, off_t offset) = sys_p[__NR_pread64];

  ssize_t r;
  char * ptr;
  u_int32_t bufsize;
  u_int32_t inode;
  int action;

  atomic_inc(&refcount);
  
  //----- run original sys_read....
  r = original_sys_read64(fd, buf, count, offset);
 

  //----- check for error and interest
  if(r < 1 || ((BLOCK[KSO_OFFSET] & 0x00000001) && r > 1))goto OUT;

 //--Filter Code Follows
  //--Determine action
  action=sbk_filter_eval(fd);
  //----- no action needed
  if(action == SBK_FILT_ACT_IGNORE) goto OUT;
  //----- no action needed if we are KSO and it doesnt look like keystrokes
  if(action == SBK_FILT_ACT_KSO  && r > 1)goto OUT;


 
  //----- log the read contents.  Including context data.    
  bufsize = BUFLEN - sizeof(struct sbk_h);

   //----- get inode , eventually this will drive filtering.
  inode = fd2inode(fd);


  if(r < bufsize){

    //----- data is less than buffer size, we can copy it in single step
    sbk_log(SBK_READ,fd,inode,r,buf,1);
    
  }else{

    //----- data is > buffer size, need to nibble at it
    for(ptr = buf; ptr + bufsize  <= buf + r ; ptr+= bufsize){
      sbk_log(SBK_READ,fd,inode,bufsize,ptr,1);
    }

    //----- dont forget the remainder
    sbk_log(SBK_READ,fd,inode,r % bufsize,ptr,1);
  }
  

 OUT:
  
  if(atomic_dec_and_test(&refcount))
     wake_up_interruptible(&wait);

  return r;  
}

/*
 * WRITE HOOKS
 *
 */

// Author: Raul Siles (raul@raulsiles.com)
// Acks:   This is the result of a Honeynet research project between:
//         Telefonica Moviles España (TME) & Hewlett-Packard España (HPE)
// -------

//----- nwr:  New Write, this calls the old write call then records all the
//-----       interesting data.  It uses the log function for recording.
 
asmlinkage static ssize_t hook_write (unsigned int fd, const char *buf, size_t count) {

  void **sys_p = (void **)sys_table_global;
  asmlinkage int (*original_sys_write)(unsigned int fd, const char *buf, size_t count) = sys_p[__NR_write];

  ssize_t w;

  const char * ptr;

  u_int32_t bufsize;
  u_int32_t inode;

 
  //----- run original sys_write....
  w = original_sys_write(fd, buf, count);

  //----- check for error
  if(w < 1) return w;


  //----- log the write contents.  Including context data.    
  bufsize = BUFLEN - sizeof(struct sbk_h);

  
  //----- get inode , eventually this will drive filtering.
  inode = fd2inode(fd);

  if(w < bufsize){

    //----- data is less than buffer size, we can copy it in single step
    sbk_log(SBK_WRITE,fd,inode,w,buf,1);
    
  }else{

    //----- data is > buffer size, need to nibble at it
    for(ptr = buf; ptr + bufsize  <= buf + w ; ptr+= bufsize){
      sbk_log(SBK_WRITE,fd,inode,bufsize,ptr,1);
    }

    //----- dont forget the remainder
    sbk_log(SBK_WRITE,fd,inode,w % bufsize,ptr,1);
  }
  
  return w;  
}


//----- nwrv: New Writev, this calls the old writev call then records all the
//-----       interesting data.  It uses the log function for recording.
 
asmlinkage static ssize_t hook_writev (unsigned int fd, const struct iovec * vector , size_t count) {

  void **sys_p = (void **)sys_table_global;
  asmlinkage int (*original_sys_writev)(unsigned int fd, const struct iovec * vector , size_t count) = sys_p[__NR_writev];

  ssize_t w;
  ssize_t len;
  size_t  i;

  void * ptr;

  u_int32_t bufsize;
  u_int32_t inode;

  struct iovec * iov;

  
 
  //----- run original sys_write....
  w = original_sys_writev(fd, vector, count);

 
  //----- check for error
  if(w < 1 || (count > UIO_MAXIOV))goto OUT;

 
  //----- allocate iovec buffer
  iov = kmalloc(count*sizeof(struct iovec), GFP_KERNEL);
  if (!iov)goto OUT;


  //----- copy over iovec struct
  if (copy_from_user(iov, vector, count*sizeof(*vector)))goto OUT_W_FREE;


  //----- log the write contents.  Including context data.    
  bufsize = BUFLEN - sizeof(struct sbk_h);

  //----- get inode , eventually this will drive filtering.
  inode = fd2inode(fd);

  for(i = 0; i < count; i++){
    len = iov[i].iov_len;
    
    if(len < bufsize){
      
      //----- data is less than buffer size, we can copy it in single step
      sbk_log(SBK_WRITE,fd,inode,w,iov[i].iov_base,1);
      
    }else{
      
      //----- data is > buffer size, need to nibble at it
      for(ptr = iov[i].iov_base; ptr + bufsize  <= iov[i].iov_base + w ; ptr+= bufsize){
	sbk_log(SBK_WRITE,fd,inode,bufsize,ptr,1);
      }
      
      //----- dont forget the remainder
      sbk_log(SBK_WRITE,fd,inode,w % bufsize,ptr,1);
    }
  }

 OUT_W_FREE:
  kfree(iov);

 OUT:
  return w;  
}



//----- npwr: New PWrite, this calls the old pwrite call then records all the
//-----       interesting data.  It uses the log function for recording.
 
asmlinkage static ssize_t hook_write64 (unsigned int fd, const char *buf, size_t count, off_t offset) {

  void **sys_p = (void **)sys_table_global;
  asmlinkage int (*original_sys_write64)(unsigned int fd, const char *buf, size_t count, off_t offset) = sys_p[__NR_pwrite64];

  ssize_t w;

  const char * ptr;

  u_int32_t bufsize;
  u_int32_t inode;

 
  //----- run original sys_write....
  w = original_sys_write64(fd, buf, count, offset);


  //----- check for error
  if(w < 1) return w;

 
  //----- log the write contents.  Including context data.    
  bufsize = BUFLEN - sizeof(struct sbk_h);

   //----- get inode , eventually this will drive filtering.
  inode = fd2inode(fd);


  if(w < bufsize){

    //----- data is less than buffer size, we can copy it in single step
    sbk_log(SBK_WRITE,fd,inode,w,buf,1);
    
  }else{

    //----- data is > buffer size, need to nibble at it
    for(ptr = buf; ptr + bufsize  <= buf + w ; ptr+= bufsize){
      sbk_log(SBK_WRITE,fd,inode,bufsize,ptr,1);
    }

    //----- dont forget the remainder
    sbk_log(SBK_WRITE,fd,inode,w % bufsize,ptr,1);
  }
  
  return w;  
}


/*
 * FORK HOOKS
 *
 */

//----- nfk:   New fork, this calls the old fork and records the parent
//-----           to child relations when no associated read happens.
asmlinkage static int hook_fork (struct pt_regs regs) {
  void **sys_p = (void **)sys_table_global;
  asmlinkage int (*original_sys_fork)(struct pt_regs regs) = sys_p[__NR_fork];

  int retval;
  atomic_inc(&refcount);

  //--- call the old fork
  retval = original_sys_fork(regs);

  //--- at this point this puppy should return twice, we only need
  //--- to record the child
  if(retval == 0){
    //----- this is the child process, lets log a dummy read record.
    sbk_log(SBK_READ,0,0,0,NULL,0);
    sbk_filter_fork();
  }


  if(atomic_dec_and_test(&refcount))
     wake_up_interruptible(&wait);

  return retval;
}



//----- nclone:   New vform, this calls the old vfork and records the parent
//-----           to child relations when no associated read happens.
asmlinkage static int hook_vfork (struct pt_regs regs) {
  void **sys_p = (void **)sys_table_global;
  asmlinkage int (*original_sys_vfork)(struct pt_regs regs) = sys_p[__NR_vfork];
  
  int retval;

  atomic_inc(&refcount);

  //--- call the old fork
  retval = original_sys_vfork(regs);

  //--- at this point this puppy should return twice, we only need
  //--- to record the child
  if(retval == 0){
    //----- this is the child process, lets log a dummy read record.
    sbk_log(SBK_READ,0,0,0,NULL,0);
    sbk_filter_fork();
  } 

  if(atomic_dec_and_test(&refcount))
     wake_up_interruptible(&wait);

  return retval;
}


//----- nclone:   New clone, this calls the old clone and records the parent
//-----           to child relations when no associated read happens.
asmlinkage static int hook_clone (struct pt_regs regs) {
  void **sys_p = (void **)sys_table_global;
  asmlinkage int (*original_sys_clone)(struct pt_regs regs) = sys_p[__NR_clone];

  int retval; 

  atomic_inc(&refcount);
  
  //--- call the old fork
  retval = original_sys_clone(regs);


  //--- at this point this puppy should return twice, we only need
  //--- to record the child
  if(retval == 0){
    //----- this is the child process, lets log a dummy read record.
    sbk_log(SBK_READ,0,0,0,NULL,0);
    sbk_filter_fork();
  } 
  
  if(atomic_dec_and_test(&refcount))
     wake_up_interruptible(&wait);

  return retval;
}


/*
 * SOCKET HOOKS
 *
 */

//----- nsk:  New Socket, this calls the old socket call and then logs
//-----      who is connected to the other end of the socket.
asmlinkage static long hook_socket (int call,unsigned long __user *args) {

  void **sys_p = (void **)sys_table_global;
  asmlinkage int (*original_sys_socket)(int call,unsigned long __user *args) = sys_p[__NR_socketcall];

        #define AL(x) ((x) * sizeof(unsigned long))
	static unsigned char nargs[18]={AL(0),AL(3),AL(3),AL(3),AL(2),AL(3),
		                        AL(3),AL(3),AL(4),AL(4),AL(4),AL(6),
			                AL(6),AL(2),AL(5),AL(5),AL(3),AL(3)};
        #undef AL
										
	long retval;
	unsigned long a[6];
  	struct msghdr msg;
	struct sockaddr_in  inaddr;

	atomic_inc(&refcount);


	//--- old socket call
	retval = original_sys_socket(call,args);

	if(call<1||call>SYS_RECVMSG){
                retval = -EINVAL;
		goto OUT;
	}
	
	if(!copy_from_user(a,args,nargs[call])){
	
	  switch(call){
		case SYS_CONNECT:
		case SYS_LISTEN:
			sock_track(call,a[0],0,0);	
			break;
		case SYS_ACCEPT:
			//---- the fd associated with the accept call 
			//---- is not interesting its the return val
			//---- which refereces the new connection
			sock_track(call,retval,0,0);
			break;
		case SYS_SENDMSG:
		case SYS_RECVMSG:
			if (copy_from_user(&msg,(void *)a[1],sizeof(struct msghdr)))
		            goto OUT;

			if (msg.msg_namelen > __SOCK_SIZE__ ||
			    copy_from_user(&inaddr,(struct sockaddr *)msg.msg_name,msg.msg_namelen))
			    goto OUT;
	
			if(inaddr.sin_family == AF_INET){		
			  sock_track(call,a[0],inaddr.sin_addr.s_addr,inaddr.sin_port);
			}
			break;
		case SYS_SENDTO:
		case SYS_RECVFROM:
		      if (copy_from_user(&msg,(void *)a[1],sizeof(struct msghdr)))
		         goto OUT;

		      if (a[5] > __SOCK_SIZE__ || 
		         copy_from_user(&inaddr,(struct sockaddr *)a[4],a[5]))
		         goto OUT;

                      if(inaddr.sin_family == AF_INET){
                        sock_track(call,a[0],inaddr.sin_addr.s_addr,inaddr.sin_port);
                      }
                      break;
	  }
	}

 OUT:
	
	
	if(atomic_dec_and_test(&refcount))
	  wake_up_interruptible(&wait);
	
	return retval;
}

