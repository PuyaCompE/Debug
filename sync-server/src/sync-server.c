#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/limits.h>
#include <json.h>
#include <libubox/uloop.h>
#include <libubox/list.h>
#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <fcntl.h>

#undef NDEBUG
#include <assert.h>

#define SYNC_OBJ_NAME "sync"
#define SYNC_RUNTIME_DIR "/tmp/sync-server"
#define SYNC_SCRIPTS_DIR "/lib/sync-server/scripts"
#define SYNC_DEV_LIST_FILE "/tmp/sync-server/mesh_dev_list"
#define SYNC_UNBIND_DEV_LIST_FILE "/tmp/sync-server/unbind_dev_list"

#define SYNC_PROBE_PROG SYNC_SCRIPTS_DIR "/probe"
#define SYNC_REQUEST_PROG SYNC_SCRIPTS_DIR "/request"
#define SYNC_SHORT_REQUEST_PROG SYNC_SCRIPTS_DIR "/short-request"
#define SYNC_CONFIG_PROG SYNC_SCRIPTS_DIR "/sync-config"
#define SYNC_GET_INFO_PROG SYNC_SCRIPTS_DIR "/get-info"
#define SYNC_DELETE_INFO_PROG SYNC_SCRIPTS_DIR "/delete-info"
#define SYNC_MERGE_PROG SYNC_SCRIPTS_DIR "/merge-cfg"
#define SYNC_DETECT_RE_PROG SYNC_SCRIPTS_DIR "/detect-re"
#define SYNC_FORCE_SYNC_PROG SYNC_SCRIPTS_DIR "/force-sync"


/**
 * mesh ip cache file:
 * filename format is : /tmp/sync-server/mesh_ip_{device_id}
 */
#define MESH_IP_FILE_PREFIX "/tmp/sync-server/mesh_ip_%s"
/**
 * deco devices directory storing device ip file used for dropbear server
 */
#define DIR_DECO_DEV "/tmp/deco_dev/"

/* TODO: add random seconds to avoid collision? */
#define PROBE_DEFAULT_TIMEOUT (10 * 60 * 1000)
#define PROBE_DEFAULT_BOOST_TIMEOUT (10 * 1000)
#define PROBE_DEFAULT_BOOST_COUNT (4)
#define DETECT_RE_TIMEOUT (40 * 1000)

#define SYNC_MAX_DEVICES (32)

#define SYNC_RESET_OPCODE (0x4022)
#define SYNC_BIND_OPCODE (0x420B)

#define LOG(fmt, ...) fprintf(stderr, "sync-server:%s:%d: " fmt "\n",    \
                              __func__, __LINE__, ##__VA_ARGS__)

#define DEFAULT_HOTPLUG_PATH    "/sbin/hotplug-call"
#define TMP_FAP_IP              "/tmp/fap_ip"

static struct ubus_context *ctx;
static struct blob_buf b;
static pid_t pid;
static json_object *devlist = NULL;
static const char *myid = NULL;
static json_object *mydev = NULL;
static const char* loopback_ip = "127.0.0.1";
static const char* short_tmp_conn = "short";

// add by liujn
static char fap_lanip[15] = {0};

struct request_data
{
    struct list_head list;
    struct uloop_process proc;
    struct ubus_request_data req;
    char infile[PATH_MAX];
    char outfile[PATH_MAX];
    bool async;
    bool saved;
    bool loaded;
};

LIST_HEAD(request_list);

enum {
NOT_SYNC,
SYNC_RUNNING,
SYNC_SUCCESS,
SYNC_FAIL
};

struct probe_data
{
    struct uloop_process probe_proc;
    struct uloop_process config_proc;
    struct uloop_process get_info_proc;
	struct uloop_process delete_info_proc;
    
    struct uloop_timeout timeout;
    int boost_count;
    int boost_timeout;
    int boost_specified;
    char infile[PATH_MAX];
    char outfile[PATH_MAX];
    bool busy;
    bool dirty; 
	bool update_dirty;
};
static struct probe_data probe_data;

struct detect_re_data
{
    struct uloop_process detect_re_proc;
    
    struct uloop_timeout timeout;
    int detect_re_timeout;
    bool busy;
};
static struct detect_re_data detect_re_data;

struct get_info_data
{
    struct uloop_process get_info_proc;
};
static struct get_info_data get_info_data;


struct force_sync_data
{
    struct uloop_process proc;
    struct ubus_request_data req;
};

static int request(const char *argv[], const unsigned int opcode, struct json_object *data);
static int write_to_file(int fd, const char* str);

static int
add_process(struct uloop_process *proc, const char *argv[])
{
    pid_t pid = fork();
    if (pid < 0)
    {
        LOG("Failed to fork: %s", strerror(errno));
        return -1;
    }

    if (0 == pid)
    {
        /* Child. */
        execv(*argv, (char *const *)argv);
        exit(-1);
    }

    proc->pid = pid;
    uloop_process_add(proc);
    return 0;
}

static inline int
reply_error(struct ubus_context *ctx, struct ubus_request_data *req,
            const char *errmsg)
{
    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "success", -1);
    blobmsg_add_string(&b, "errmsg", errmsg);
    ubus_send_reply(ctx, req, b.head);
    return 0;
}

static inline bool
is_enable_tmp_security(void)
{
    if (access(DIR_DECO_DEV, 0) == 0)
    {
        return true;
    }

    return false;
}

static inline bool
check_proc_ret(const char *prog, int ret)
{
    if (WIFEXITED(ret) && WEXITSTATUS(ret) == 0)
    {
        LOG("%s process exited successfully", prog);
        return true;
    }
    else if (WIFSIGNALED(ret))
    {
        LOG("%s process was killed by signal %d", prog, WTERMSIG(ret));
    }
    else
    {
        LOG("%s process exited with code %d", prog, WEXITSTATUS(ret));
    }

    return false;
}

static void probe_timeout_cb(struct uloop_timeout *timeout);

static void tmp_security_handle(struct json_object *dev)
{   
    int ip_fd;
    char ip_file[50];
    char banner[4];

    json_object *ip = json_object_object_get(dev, "ip");

    if (ip)
    {   
        snprintf(ip_file, sizeof(ip_file), DIR_DECO_DEV "%s", json_object_get_string(ip));
        if((ip_fd = open(ip_file, O_RDWR, 0600)) < 0) 
        {
            LOG("error open deco_dev file %s:%s\n", ip_file, strerror(errno));
        }
        else 
        {
            if (json_object_object_get(dev, "tps"))
            {   
                memset(banner, 0, sizeof(banner));
                read(ip_fd, banner, 3);                        
                if (strcmp(banner, "TPS")) 
                {
                    lseek(ip_fd, 0, SEEK_SET);
                    if (write_to_file(ip_fd, "TPS")< 0)
                    {
                        LOG("error writing deco_dev file %s:%s\n", ip_file, strerror(errno));
                    }                        
                }
            }
            else
            {
                if (lseek(ip_fd, 0, SEEK_END) != 0)
                {
                    ftruncate(ip_fd, 0);
                }
            } 
            close(ip_fd);  
        } 
    }
}

static void
probe_done(bool success)
{
    int timeout = 0;
    probe_data.busy = false;
    if (probe_data.boost_specified > 0)
    {		
        timeout = probe_data.boost_specified;
        probe_data.boost_specified = 0;
    }
    else if (probe_data.boost_count > 0)
    {
        if (success)
        {
            probe_data.boost_count--;
        }
        timeout = probe_data.boost_timeout;
    }
    else
    {
        timeout = PROBE_DEFAULT_TIMEOUT;
    }

    uloop_timeout_set(&probe_data.timeout, timeout);
}

static void
sync_config_proc_cb(struct uloop_process *proc, int ret)
{
    probe_done(check_proc_ret("sync-config", ret));
}

static void
get_info_proc_cb(struct uloop_process *proc, int ret)
{
    bool success = check_proc_ret("get_info", ret);
    probe_done(success);
    if(success)
    {
        uloop_timeout_set(&probe_data.timeout, 0);
    }
}

static void
delete_info_proc_cb(struct uloop_process *proc, int ret)
{
    probe_done(check_proc_ret("delete-info", ret));
}

static int
write_to_file(int fd, const char* str)
{
  int ret;
  unsigned int wpos, wsize;

  wsize = (unsigned int)(strlen(str)); 
  wpos = 0;
  while(wpos < wsize) {
    if((ret = write(fd, str + wpos, wsize-wpos)) < 0) {
      LOG("error writing file %s\n", strerror(errno));
      return -1;
    }

	/* because of the above check for ret < 0, we can safely cast and add */
    wpos += (unsigned int)ret;
  }

  return wpos;
}

static void
output_ip_file(const char* dev_id,struct json_object *dev)
{
    int fd;
    char filename[128];
    struct json_object* dev_ip;

    if(!dev_id || !dev)
    {
        return;
    }

    dev_ip = json_object_object_get(dev, "ip");

    if(!dev_ip)
    {
        return;
    }

    snprintf(filename, 128 , MESH_IP_FILE_PREFIX, dev_id);
    if((fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, 0644)) < 0) {
        LOG("json_object_to_file: error opening file %s: %s\n",
	         filename, strerror(errno));
        return ;
    }

    write_to_file(fd, json_object_get_string(dev_ip));
    close(fd);
}

// add by liujn
void syncserver_call_hotplug_fapip(const char *ip, const char *event)
{
    int pid;
    char *argv[3];
    char *hotplug_cmd_path = DEFAULT_HOTPLUG_PATH;

    pid = fork();
    if (pid < 0)
    {
        LOG("fork failed.");
        return;
    }

    if (pid == 0) {
        setenv("FAPADDR", ip, 1);
        setenv("FAPEVENT", event, 1);

        argv[0] = hotplug_cmd_path;
        argv[1] = "ip";
        argv[2] = NULL;
        execvp(argv[0], argv);
        exit(127);
        return ;
    }
    else
    {
        LOG("wait pid");
    }    
}

static void
output_devlist()
{
    int bind_cnt = 0;
    int unbind_cnt = 0;
    int bind_fd, unbind_fd;
    int fap_fd;
    char tmp_str[256];

    if((bind_fd = open(SYNC_DEV_LIST_FILE, O_WRONLY | O_TRUNC | O_CREAT, 0644)) < 0) {
        LOG("json_object_to_file: error opening file %s: %s\n",
	         SYNC_DEV_LIST_FILE, strerror(errno));
        return ;
    }
    if((unbind_fd = open(SYNC_UNBIND_DEV_LIST_FILE, O_WRONLY | O_TRUNC | O_CREAT, 0644)) < 0) {
        LOG("json_object_to_file: error opening file %s: %s\n",
	         SYNC_UNBIND_DEV_LIST_FILE, strerror(errno));
        goto out;
    }    
    write_to_file(bind_fd, "{");
    write_to_file(unbind_fd, "{");    
    

    json_object_object_foreach(devlist, devid, dev)
    {
        if (dev)
        {
            json_object *role = json_object_object_get(dev, "role");

            if (is_enable_tmp_security())
            {   
               tmp_security_handle(dev);
            }

            // add by liujn
            if (role && 0 == strcmp(json_object_get_string(role), "AP"))
            {
                //RE find self and ap,stop boost
                json_object *myself = json_object_object_get(devlist, myid);
                json_object *my_role = NULL;
                if (myself)
                {
                    my_role = json_object_object_get(myself, "role");
                }
                if (my_role && 0 == strcmp(json_object_get_string(my_role), "RE") && probe_data.boost_count > 1)
                {
                    int count_down_ap = json_object_get_int(json_object_object_get(dev, "countdown"));
                    int count_down_myself = json_object_get_int(json_object_object_get(myself, "countdown"));
                    if (count_down_ap == 4 && count_down_myself == 4)
                    {
                        probe_data.boost_count = 0;
                    }
                }
                
                json_object *lanip = json_object_object_get(dev, "ip");
                LOG("lanip: %s\n", json_object_get_string(lanip));
                if (lanip && strcmp(json_object_get_string(lanip), fap_lanip) != 0)
                {
                    LOG("fap ip changes\n");
                    if((fap_fd = open(TMP_FAP_IP, O_WRONLY | O_TRUNC | O_CREAT, 0644)) < 0) {
                        LOG("json_object_to_file: error opening file %s: %s\n",
                             TMP_FAP_IP, strerror(errno));
                        close(fap_fd);
                    }
                    else
                    {
                        memcpy(fap_lanip, json_object_get_string(lanip), 15);
                        LOG("fap_lanip: %s\n", fap_lanip);
                        syncserver_call_hotplug_fapip(fap_lanip, "FAPIPCHANGE");

                        if (write_to_file(fap_fd, fap_lanip) < 0)
                            close(fap_fd);
                    }
                }
            } 

            if (role && strcmp(json_object_get_string(role), "UNBIND"))
            {
                snprintf(tmp_str, sizeof(tmp_str), "%s\"%s\":", bind_cnt ? ",":"", devid);
                if (write_to_file(bind_fd, tmp_str)< 0)
                    goto out;
                
                if (write_to_file(bind_fd, json_object_to_json_string_ext(dev, JSON_C_TO_STRING_PLAIN)) < 0)
                    goto out;

                output_ip_file(devid, dev);
                bind_cnt++;
            }
            else 
            {           
                snprintf(tmp_str, sizeof(tmp_str), "%s\"%s\":", unbind_cnt ? ",":"", devid);
                if (write_to_file(unbind_fd, tmp_str)< 0)
                    goto out;
                
                if (write_to_file(unbind_fd, json_object_to_json_string_ext(dev, JSON_C_TO_STRING_PLAIN)) < 0)
                    goto out;

                unbind_cnt++;
            }

        }
    }

    write_to_file(bind_fd, "}");
    write_to_file(unbind_fd, "}");    

out:   
    close(bind_fd);
    close(unbind_fd);

    if (is_enable_tmp_security())
    {
        system("/sbin/fw_input.sh remove_deco");   
    }

    return;
}

static void
probe_proc_cb(struct uloop_process *proc, int ret)
{
    int rc;
    struct json_object *root = NULL;
    bool succ = false;

    if (probe_data.dirty)
    {
        LOG("probe data is dirty, should not process probe result.");    
        goto done;
    }

    if (check_proc_ret("probe", ret))
    {
        struct json_object *success, *errmsg;
        root = json_object_from_file(probe_data.outfile);
        if (NULL == root)
        {
            LOG("Failed to read json file");
            goto done;
        }

        success = json_object_object_get(root, "success");
        if (json_object_get_int(success) < 0)
        {
            errmsg = json_object_object_get(root, "errmsg");
            LOG("Failed to probe: %s",
                errmsg == NULL ? "unknown error" : json_object_get_string(errmsg));
            goto done;
        }

        /*search for which device has extended_attr*/
        struct json_object * extra_support = json_object_new_object();  
        if (devlist)
        {
            json_object_object_foreach(devlist, devid, dev)
            {
                if (dev)
                {
                    struct json_object *extended_attr = json_object_object_get(dev,"extended_attr");
                    if(extended_attr)
                    {
                        json_object_object_add(extra_support, devid, extended_attr);
                        json_object_get(extended_attr);
                    }
                }
            }
            const char *ss = json_object_to_json_string(extra_support);
            LOG("extra_support: %s \n", ss);
        }

        if (devlist != NULL)
        {
            rc = json_object_put(devlist);
            assert(rc == 1);
        }

        devlist = json_object_object_get(root, "data");
        if (NULL == devlist)
        {
            goto done;
        }

        if (json_object_is_type(devlist, json_type_object))
        {
        	struct json_object *to_delete_info;
        	struct json_object *to_get_info;
            struct json_object *to_reset;        
            struct json_object *to_bind;             
            struct json_object *to_update;

            int i;

            json_object_get(devlist);

            if (myid)
            {
                mydev = json_object_object_get(devlist, myid);
                if (mydev)
                {
                    json_object_object_add(mydev, "myself", json_object_new_boolean(true));
                }
                else
                {
                    LOG("WARNING: probe failed to find myself");
                }
            }

            /*add extended_attr to device*/
            json_object_object_foreach(extra_support, key, val)
            {
                if (val)
                {
                    struct json_object * tempdev = json_object_object_get(devlist, key);
                    if (tempdev)
                    {
                        json_object_object_add(tempdev, "extended_attr", val);
                        json_object_get(val);
                    }
                }
            }
            json_object_put(extra_support);

			to_delete_info = json_object_object_get(root, "to_delete_info");
            if (to_delete_info && json_object_is_type(to_delete_info, json_type_array))
            {
                const char *argv_del_info[SYNC_MAX_DEVICES+2] = {SYNC_DELETE_INFO_PROG};
                const char **devid_list_del_info = &argv_del_info[1];
                int count_del_info = json_object_array_length(to_delete_info);
                if (count_del_info > SYNC_MAX_DEVICES)
                {
                    count_del_info = SYNC_MAX_DEVICES;
                }
                for (i = 0; i < count_del_info; i++)
                {
                    struct json_object *tmp_del_info = json_object_array_get_idx(to_delete_info, i);
                    if (NULL == tmp_del_info)
                    {
                        break;
                    }
                    devid_list_del_info[i] = json_object_get_string(tmp_del_info);
                }                
				if (i > 0)
                {
                    devid_list_del_info[i] = NULL;
                    if (add_process(&probe_data.delete_info_proc, argv_del_info) < 0)
                    {
                        LOG("Failed to launch process for delete_info");
                        goto done;
                    }
				goto done_still_busy;
                }
            }

			to_get_info = json_object_object_get(root, "to_get_info");
            if (to_get_info && json_object_is_type(to_get_info, json_type_array))
            {
                const char *argv_info[SYNC_MAX_DEVICES*2+2] = {SYNC_GET_INFO_PROG};
                const char **ip_list_info = &argv_info[1];
                int count_info = json_object_array_length(to_get_info);
                if (count_info > SYNC_MAX_DEVICES*2)
                {
                    count_info = SYNC_MAX_DEVICES*2;
                }
                for (i = 0; i < count_info; i++)
                {
                    struct json_object *tmp_info = json_object_array_get_idx(to_get_info, i);
                    if (NULL == tmp_info)
                    {
                        break;
                    }
                    ip_list_info[i] = json_object_get_string(tmp_info);
                }                
				if (i > 0)
                {
                    ip_list_info[i] = NULL;
                    if (add_process(&probe_data.get_info_proc, argv_info) < 0)
                    {
                        LOG("Failed to launch process for get_info");
                        goto done;
                    }
				goto done_still_busy;
                }
            }

            to_reset = json_object_object_get(root, "to_reset");
            if (to_reset && json_object_is_type(to_reset, json_type_array))
            {
                const char *argv[SYNC_MAX_DEVICES*2+5] = {SYNC_REQUEST_PROG};                
                const char **ip_list = &argv[4];
                int j = 0;

                char bind_state[SYNC_MAX_DEVICES][8];
                int count = json_object_array_length(to_reset);
                if (count > SYNC_MAX_DEVICES)
                {
                    count = SYNC_MAX_DEVICES;
                }

                struct json_object *remote_dev_list = json_object_new_array();
                for (i = 0; i < count; i++)
                {
                    struct json_object *tmp = json_object_array_get_idx(to_reset, i);
                    if (NULL == tmp)
                    {
                        break;
                    }

                    const char *remote_id = json_object_get_string(tmp);
                    struct json_object *dev = json_object_object_get(devlist, remote_id);
                    if (dev)
                    {
                        struct json_object *tmpip = json_object_object_get(dev, "ip");
                        if (NULL != tmp)
                        {
                            snprintf(bind_state[j], sizeof(bind_state[j]), "1");
                            ip_list[j * 2] = json_object_get_string(tmpip);
                            ip_list[j * 2 + 1] = bind_state[j];               
                            j++;

                            struct json_object * remote_dev = json_object_new_object();                    
                            json_object_object_add(remote_dev, "device_id", json_object_new_string(remote_id));
                            json_object_array_add(remote_dev_list, remote_dev);
                        }
                    }
                                   
                }

                if (j > 0)
                {
                    ip_list[j*2] = NULL;
                    struct json_object * params = json_object_new_object();
                    struct json_object * data = json_object_new_object();
                    json_object_object_add(params, "device_list", remote_dev_list);
                    if (myid)
                    {
                        json_object_object_add(params, "from", json_object_new_string(myid));
                    }
                    json_object_object_add(data, "params", params);
                    if (request(argv, SYNC_RESET_OPCODE, data) < 0)
                    {
                        LOG("Failed to launch process for sync");
                        json_object_put(data);
                        goto done;
                    }
                    json_object_put(data);
                }
            }

            to_bind = json_object_object_get(root, "to_bind");
            if (mydev && to_bind && json_object_is_type(to_bind, json_type_array))
            {
                const char *argv[SYNC_MAX_DEVICES*2+5] = {SYNC_REQUEST_PROG};                
                const char **ip_list = &argv[4];
                char bind_state[8];

                struct json_object *tmp = json_object_object_get(mydev, "ip");
                if (NULL != tmp)
                {
                    snprintf(bind_state, sizeof(bind_state), "1");
                    ip_list[0] = json_object_get_string(tmp);
                    ip_list[1] = bind_state;

                    int count = json_object_array_length(to_bind);
                    if (count > SYNC_MAX_DEVICES)
                    {
                        count = SYNC_MAX_DEVICES;
                    }

                    struct json_object *remote_dev_list = json_object_new_array();
                    for (i = 0; i < count; i++)
                    {
                        struct json_object *tmp = json_object_array_get_idx(to_bind, i);
                        if (NULL == tmp)
                        {
                            break;
                        }

                        const char *remote_id = json_object_get_string(tmp);
                        struct json_object *dev = json_object_object_get(devlist, remote_id);
                        if (dev)
                        {
                            struct json_object * remote_dev = json_object_new_object();                    
                            json_object_object_add(remote_dev, "device_id", json_object_new_string(remote_id));
                            json_object_array_add(remote_dev_list, remote_dev);
                        }
                                   
                    }              

                    if (i > 0)
                    {
                        ip_list[2] = NULL;
                        struct json_object * params = json_object_new_object();
                        struct json_object * data = json_object_new_object();
                        json_object_object_add(params, "device_list", remote_dev_list);
                        json_object_object_add(params, "generator", json_object_new_string("sync"));
                        json_object_object_add(data, "params", params);
                        if (request(argv, SYNC_BIND_OPCODE, data) < 0)
                        {
                            LOG("Failed to launch process for sync");
                            json_object_put(data);
                            goto done;
                        }
                        json_object_put(data);
                    }
                }
            }            

			if (!probe_data.update_dirty)
			{
            to_update = json_object_object_get(root, "to_update");
            if (to_update && json_object_is_type(to_update, json_type_array))
            {
                const char *argv[SYNC_MAX_DEVICES*2+2] = {SYNC_CONFIG_PROG};
                const char **ip_list = &argv[1];
                char bind_state[SYNC_MAX_DEVICES][8];
                int count = json_object_array_length(to_update);
                if (count > SYNC_MAX_DEVICES)
                {
                    count = SYNC_MAX_DEVICES;
                }

                for (i = 0; i < count; i++)
                {
                    struct json_object *tmp = json_object_array_get_idx(to_update, i);
                    if (NULL == tmp)
                    {
                        break;
                    }

                    snprintf(bind_state[i], sizeof(bind_state[i]), "1");
                    ip_list[i*2] = json_object_get_string(tmp);
                    ip_list[i*2+1] = bind_state[i];                    
                }

                if (i > 0)
                {
                    ip_list[i*2] = NULL;
                    if (add_process(&probe_data.config_proc, argv) < 0)
                    {
                        LOG("Failed to launch process for sync");
                        goto done;
                    }
                    goto done_still_busy;

                }
            }
			}
        }
        else
        {
            devlist = NULL;
        }

        succ = true;
    }

done:
    probe_done(succ);

done_still_busy:
    if (NULL != root)
    {
        rc = json_object_put(root);
        assert(rc == 1);
    }

    if (strcmp(probe_data.infile, "-") != 0)
    {
        unlink(probe_data.infile);
    }
    if(NULL != devlist)
    {
        output_devlist();        
    }
    unlink(probe_data.outfile);
}

static bool is_onboarding()
{
    int status = 0;
    FILE* fp = fopen("/tmp/onboarding", "r");
 
    if (fp == NULL)
    {
        LOG("/tmp/onboarding not exist");
        return false;
    }
    if (fscanf(fp, "%d", &status) == EOF)
    {
        fclose(fp);
        return false;
    }

    fclose(fp);
    if (status == 1)  return true;
    return false;
}


static int
probe(const char **err)
{
    if (probe_data.busy)
    {
        LOG("probe process is running");
        if (err != NULL) *err = "running";
        return -1;
    }

    if (myid && devlist)
    {
        mydev = json_object_object_get(devlist, myid);
        if (mydev) 
        {
            json_object *my_role = json_object_object_get(mydev, "role");
            //only when onboarding ,  RE  dont send probe
            if (my_role && 0 == strcmp(json_object_get_string(my_role), "RE"))
            {
                if (is_onboarding())
                {
                    LOG("is onboarding, probe wait");
                    uloop_timeout_set(&probe_data.timeout, PROBE_DEFAULT_BOOST_TIMEOUT);
                    //if use as probe(NULL), dont set err
                    if (err != NULL) *err = "onboarding";
                    return -1;
                }
            }
        }
    }

    probe_data.dirty = false;
    probe_data.busy = true;
    snprintf(probe_data.outfile, PATH_MAX, "%s/probe-output-%u-%u",
             SYNC_RUNTIME_DIR, (unsigned int)time(NULL), (unsigned int)pid);
    if (NULL == devlist)
    {
        snprintf(probe_data.infile, PATH_MAX, "-");
    }
    else
    {
        snprintf(probe_data.infile, PATH_MAX, "%s/probe-input-%u-%u",
                 SYNC_RUNTIME_DIR, (unsigned int)time(NULL), (unsigned int)pid);
        if (json_object_to_file(probe_data.infile, devlist) < 0)
        {
            LOG("Failed to write devlist to input file");
            *err = "input";
            goto error;
        }
    }

    {
        const char *argv[] = {
            SYNC_PROBE_PROG,
            probe_data.infile, probe_data.outfile, NULL
        };
        if (add_process(&probe_data.probe_proc, argv) < 0)
        {
            LOG("Failed to launch process for probing");
            *err = "process";
            goto error;
        }
    }

    return 0;
error:
    probe_done(false);
    return -1;
}

static void
probe_timeout_cb(struct uloop_timeout *timeout)
{
    probe(NULL);
}

enum
{
    REQUEST_OPCODE,
    REQUEST_TARGET_TYPE,
    REQUEST_TARGET_ID,
    REQUEST_INCLUDE_MYSELF,
    REQUEST_MY_ROLE,
    REQUEST_DATA,
    REQUEST_SAVE,
    REQUEST_LOAD,
    REQUEST_SCRIPT,
    REQUEST_LOOPBACK,
    REQUEST_SUPPORT_FEATURE,
    REQUEST_EXCLUDE_FEATURE,
    REQUEST_CONN_TYPE,
    __REQUEST_MAX,
};

static const struct blobmsg_policy request_policy[__REQUEST_MAX] = {
    [REQUEST_OPCODE] = {"opcode", BLOBMSG_TYPE_UNSPEC},
    [REQUEST_TARGET_TYPE] = {"target_type", BLOBMSG_TYPE_STRING},
    [REQUEST_TARGET_ID] = {"target_id", BLOBMSG_TYPE_STRING},
    [REQUEST_INCLUDE_MYSELF] = {"include_myself", BLOBMSG_TYPE_BOOL},
    [REQUEST_MY_ROLE] = {"my_role", BLOBMSG_TYPE_STRING},
    [REQUEST_DATA] = {"data", BLOBMSG_TYPE_TABLE},
    [REQUEST_SAVE] = {"save", BLOBMSG_TYPE_STRING},
    [REQUEST_LOAD] = {"load", BLOBMSG_TYPE_STRING},
    [REQUEST_SCRIPT] = {"script", BLOBMSG_TYPE_STRING}, 
    [REQUEST_LOOPBACK] = {"loopback", BLOBMSG_TYPE_BOOL},
    [REQUEST_SUPPORT_FEATURE] = {"support_feature", BLOBMSG_TYPE_STRING},
    [REQUEST_EXCLUDE_FEATURE] = {"exclude_feature", BLOBMSG_TYPE_STRING},
    [REQUEST_CONN_TYPE] = {"conn_type", BLOBMSG_TYPE_STRING},
};

static void
request_clean(struct request_data *r)
{
    if (!r->loaded)
    {
        unlink(r->infile);
    }
    if (!r->saved)
    {
        unlink(r->outfile);
    }
    list_del(&r->list);
    free(r);
}

static void
request_proc_cb(struct uloop_process *proc, int ret)
{
    struct request_data *r = container_of(proc, struct request_data, proc);
    bool success = check_proc_ret("request", ret);

    if (r->async)
    {
        goto done;
    }

    if (success)
    {
        blob_buf_init(&b, 0);
        if (!r->saved)
        {
            blobmsg_add_json_from_file(&b, r->outfile);
        }
        else
        {
            blobmsg_add_u32(&b, "success", 0);
        }
        ubus_send_reply(ctx, &r->req, b.head);
    }
    else
    {
        char msg[64];
        if (WIFSIGNALED(ret))
        {
            snprintf(msg, 64, "process was killed by signal %d", WTERMSIG(ret));
        }
        else
        {
            snprintf(msg, 64, "process exited with code %d", WEXITSTATUS(ret));
        }
        reply_error(ctx, &r->req, msg);
    }

    ubus_complete_deferred_request(ctx, &r->req, 0);

done:
    request_clean(r);
}

static int
is_bind_dev(struct json_object *dev)
{
    json_object *role = json_object_object_get(dev, "role");
    if (!role || !strcmp(json_object_get_string(role), "UNBIND"))
    {
        return 0;
    }
    return 1;
}

static bool
check_dev(struct json_object *dev, struct blob_attr *tb[])
{
    bool include_myself = false;
    json_object *myself = NULL;

    if (tb[REQUEST_INCLUDE_MYSELF])
    {
        include_myself = blobmsg_get_bool(tb[REQUEST_INCLUDE_MYSELF]);
    }
    LOG("check_dev : include_myself: %d", include_myself);
    myself = json_object_object_get(dev, "myself");
    if (myself && json_object_get_boolean(myself) && !include_myself)
    {
        return false;
    }

    if (tb[REQUEST_TARGET_TYPE])
    {
        const char *target_type = blobmsg_get_string(tb[REQUEST_TARGET_TYPE]);
        json_object *role = json_object_object_get(dev, "role");
        if (target_type && role
            && strcmp(target_type, "ALL") != 0 
            && strcmp(target_type, json_object_get_string(role)) != 0)
        {
            return false;
        }
    }

    if (tb[REQUEST_SUPPORT_FEATURE])
    {
        const char *support_feature = blobmsg_get_string(tb[REQUEST_SUPPORT_FEATURE]);
        json_object *feature = json_object_object_get(dev, support_feature);
        if (!feature)
        {
            return false;
        }
        if(strcmp(support_feature, "tipc") == 0 && json_object_get_int(feature) == 0)
        {
            return false;
        }
    }


    if (tb[REQUEST_EXCLUDE_FEATURE])
    {
        const char *exclude_feature = blobmsg_get_string(tb[REQUEST_EXCLUDE_FEATURE]);
        json_object *feature = json_object_object_get(dev, exclude_feature);
        if (feature)
        {
            if(strcmp(exclude_feature, "tipc") == 0 && json_object_get_int(feature) == 0)
            {
                return true;
            }
            return false;
        }
    }

    return true;
}

static int generate_random()
{
	int fd = -1;
	int randNum = 0;

	fd = open("/dev/urandom", O_RDONLY);
	if (-1 == fd)
	{
		srand((int)time(NULL));
		randNum = rand();
	}
	else
	{
		read(fd, (char *) &randNum, sizeof(int));
		close(fd);
	}

	return randNum;
}
static int
_handle_request(struct ubus_context *ctx, struct ubus_request_data *req,
                const char *argv[], struct blob_attr *tb[],
                bool async)
{
    char opcode[32];
    char prog[PATH_MAX];
    struct request_data *r = malloc(sizeof(struct request_data));

    if (r == NULL)
    {
        return reply_error(ctx, req, "memory");
    }

    memset(r, 0, sizeof(struct request_data));

    r->async = async;

    if (tb[REQUEST_LOAD])
    {
        snprintf(r->infile, PATH_MAX, "%s", blobmsg_get_string(tb[REQUEST_LOAD]));
        r->loaded = true;
    }
    else
    {
        snprintf(r->infile, PATH_MAX, "%s/request-input-%u-%u",
                 SYNC_RUNTIME_DIR, generate_random(), (unsigned int)pid);
    }

    argv[1] = r->infile;

    if (tb[REQUEST_SAVE])
    {
        snprintf(r->outfile, PATH_MAX, "%s", blobmsg_get_string(tb[REQUEST_SAVE]));
        r->saved = true;
    }
    else
    {
        snprintf(r->outfile, PATH_MAX, "%s/request-output-%u-%u",
                 SYNC_RUNTIME_DIR, generate_random(), (unsigned int)pid);
    }

    argv[2] = r->outfile;

    if (blobmsg_type(tb[REQUEST_OPCODE]) == BLOBMSG_TYPE_INT32)
    {
        snprintf(opcode, sizeof(opcode), "0x%X", blobmsg_get_u32(tb[REQUEST_OPCODE]));
        argv[3] = opcode;
    }
    else if (blobmsg_type(tb[REQUEST_OPCODE]) == BLOBMSG_TYPE_STRING)
    {
        argv[3] = blobmsg_get_string(tb[REQUEST_OPCODE]);
    }
    else
    {
        free(r);
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

    r->proc.cb = request_proc_cb;

    if (!r->loaded)
    {
        char *s = blobmsg_format_json(tb[REQUEST_DATA], true);
        if (!s)
        {
            free(r);
            return reply_error(ctx, req, "format");
        }
		
        FILE *fp = fopen(r->infile, "w");
        if (NULL == fp)
        {
            LOG("Failed to open %s", r->infile);
            free(s);
            free(r);
            return reply_error(ctx, req, "open");
        }
        fprintf(fp, "%s", s);
        fclose(fp);
        free(s);
    }

    if (tb[REQUEST_SCRIPT])
    {
        const char *script = blobmsg_get_string(tb[REQUEST_SCRIPT]);
        if (script[0] == '/')
        {
            snprintf(prog, PATH_MAX, "%s", script);
        }
        else
        {
            snprintf(prog, PATH_MAX, "%s/%s",
                     SYNC_SCRIPTS_DIR, script);
        }
        argv[0] = prog;
    }

    if (add_process(&r->proc, argv) < 0)
    {
        LOG("Failed to launch process for requesting");
        free(r);
        return reply_error(ctx, req, "process");
    }

    list_add(&r->list, &request_list);

    if (async)
    {
        blob_buf_init(&b, 0);
        blobmsg_add_u32(&b, "id", r->proc.pid);
        blobmsg_add_u32(&b, "success", 0);
        ubus_send_reply(ctx, req, b.head);
    }
    else
    {
        ubus_defer_request(ctx, req, &r->req);
    }

    return 0;
}

static int get_bind_state(void)
{
    FILE* fp = NULL;
    char result[8] = {0};

    if ((fp = popen("cat /tmp/is_binded", "r")) == NULL)
    {
        return 0;
    }
    fgets(result, sizeof(result) - 1, fp);
    pclose(fp);

    return strtoul(result, NULL, 10);

}

static int
handle_request(struct ubus_context *ctx, struct ubus_object *obj,
               struct ubus_request_data *req, const char *method,
               struct blob_attr *msg)
{
    struct blob_attr *tb[__REQUEST_MAX];
    const char *argv[SYNC_MAX_DEVICES*2+5] = {
        SYNC_REQUEST_PROG
    };
    char bind_state[SYNC_MAX_DEVICES][8];
    const char **ip_list = &argv[4];
	char state[8] = {0};
    bool loopback = false;
    int count = 0;
    int rc;

    rc = blobmsg_parse(request_policy, __REQUEST_MAX, tb, blob_data(msg), blob_len(msg));
    if (rc < 0)
    {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

    if (!tb[REQUEST_OPCODE] || !(tb[REQUEST_DATA] || tb[REQUEST_LOAD]))
    {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

    if (tb[REQUEST_LOOPBACK])
    {
        LOG("get REQUEST_LOOPBACK");
    }
    else
    {
        if (!devlist)
        {
            goto done;
        }
    }

    if (tb[REQUEST_CONN_TYPE])
    {
        const char *conn_type = blobmsg_get_string(tb[REQUEST_CONN_TYPE]);
        if (strcmp(conn_type, short_tmp_conn) == 0)
        {
            *argv = SYNC_SHORT_REQUEST_PROG;
        }
    }

    if (tb[REQUEST_MY_ROLE])
    {
        const char *my_role = blobmsg_get_string(tb[REQUEST_MY_ROLE]);
        json_object *role = mydev ? json_object_object_get(mydev, "role") : NULL;

        if (my_role && role && strcmp(my_role, json_object_get_string(role)) != 0)
        {
            goto done;
        }
    }

    if (tb[REQUEST_LOOPBACK])
    {

        loopback = blobmsg_get_bool(tb[REQUEST_LOOPBACK]);
        if (loopback)
        {
            LOG("get lookback ip");
            ip_list[count * 2] = loopback_ip;
			snprintf(state, sizeof(state) - 1, "%d", get_bind_state());
            ip_list[count * 2 + 1] = state;
            count++;
        }
        
    }
    else if (tb[REQUEST_TARGET_ID])
    {
        // format: "devid,devid"
        const char *target_id = blobmsg_get_string(tb[REQUEST_TARGET_ID]);
        char* p = (char*)target_id;
        char* tmp_id = strtok(p, ",");
        while(tmp_id != NULL)
        {
            struct json_object *dev = json_object_object_get(devlist, tmp_id/*target_id*/);
            if (dev && check_dev(dev, tb))
            {
                struct json_object *tmp = json_object_object_get(dev, "ip");
                if (NULL != tmp)
                {
                    snprintf(bind_state[count], sizeof(bind_state[count]), "%d", is_bind_dev(dev));
                    ip_list[count * 2] = json_object_get_string(tmp);
                    ip_list[count * 2 + 1] = bind_state[count];               
                    count++;
                }
            }

            tmp_id = strtok(NULL, ",");
        }
    }
    else if (tb[REQUEST_TARGET_TYPE])
    {
        json_object_object_foreach(devlist, devid, dev)
        {
            (void)devid;
            if (check_dev(dev, tb))
            {
                struct json_object *tmp = json_object_object_get(dev, "ip");
                if (NULL != tmp)
                {
                    snprintf(bind_state[count], sizeof(bind_state[count]), "%d", is_bind_dev(dev));
                    ip_list[count * 2] = json_object_get_string(tmp);
                    ip_list[count * 2 + 1] = bind_state[count];               
                    count++;                    
                }
            }
        }
    }
    else
    {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

    if (count > 0)
    {
        ip_list[count * 2] = NULL;
        return _handle_request(ctx, req, argv, tb, strcmp(method, "send") == 0);
    }

done:
    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "success", 0);
    blobmsg_add_u32(&b, "total", 0);
    ubus_send_reply(ctx, req, b.head);
    return 0;
}

static int
request(const char *argv[], const unsigned int opcode, struct json_object *data)
{
    char opcode_str[32];
    struct request_data *r = malloc(sizeof(struct request_data));

    if (r == NULL)
    {
        return -1;
    }

    memset(r, 0, sizeof(struct request_data));
    r->async = true;
    r->proc.cb = request_proc_cb;

    snprintf(r->infile, PATH_MAX, "%s/request-input-%u-%u",
             SYNC_RUNTIME_DIR, generate_random(), (unsigned int)pid);
    snprintf(r->outfile, PATH_MAX, "%s/request-output-%u-%u",
             SYNC_RUNTIME_DIR, generate_random(), (unsigned int)pid);
    snprintf(opcode_str, sizeof(opcode_str), "0x%X", opcode);

    if (json_object_to_file(r->infile, data) < 0)
    {
        LOG("Failed to write data to input file");
        free(r);
        return -1;
    }
        

    argv[0] = SYNC_REQUEST_PROG;
    argv[1] = r->infile;
    argv[2] = r->outfile;
    argv[3] = opcode_str;
    
    if (add_process(&r->proc, argv) < 0)
    {
        LOG("Failed to launch process for requesting");
        free(r);
        return -1;
    }

    list_add(&r->list, &request_list);

    return 0;
}


enum
{
    __PROBE_MAX,
};

static const struct blobmsg_policy probe_policy[__PROBE_MAX] = {
};

static int
handle_probe(struct ubus_context *ctx, struct ubus_object *obj,
             struct ubus_request_data *req, const char *method,
             struct blob_attr *msg)
{
    const char *err;
    int rc;

    uloop_timeout_cancel(&probe_data.timeout);

    rc = probe(&err);

    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "success", rc);
    if (rc < 0)
    {
        blobmsg_add_string(&b, "errmsg", err);
    }
    ubus_send_reply(ctx, req, b.head);
    return 0;
}

enum
{
    BOOST_COUNT,
    BOOST_INTERVAL,
    BOOST_BEGIN,    
    __BOOST_MAX,
};

static const struct blobmsg_policy boost_policy[__BOOST_MAX] = {
    [BOOST_COUNT] = {"count", BLOBMSG_TYPE_INT32},
    [BOOST_INTERVAL] = {"interval", BLOBMSG_TYPE_INT32},
    [BOOST_BEGIN] = {"begin", BLOBMSG_TYPE_INT32},    
};

static int
handle_boost(struct ubus_context *ctx, struct ubus_object *obj,
             struct ubus_request_data *req, const char *method,
             struct blob_attr *msg)
{
    struct blob_attr *tb[__BOOST_MAX];
    int count = PROBE_DEFAULT_BOOST_COUNT;
    int interval = PROBE_DEFAULT_BOOST_TIMEOUT;
    int begin = 0;
    int rc = blobmsg_parse(boost_policy, __BOOST_MAX, tb, blob_data(msg), blob_len(msg));
    if (rc < 0)
    {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

    if (tb[BOOST_COUNT])
    {
        count = blobmsg_get_u32(tb[BOOST_COUNT]);
    }

    if (tb[BOOST_INTERVAL])
    {
        interval = blobmsg_get_u32(tb[BOOST_INTERVAL]);
        if (interval <= 0)
        {
            return UBUS_STATUS_INVALID_ARGUMENT;
        }

        interval *= 1000;
    }

    if (tb[BOOST_BEGIN])
    {
        begin = blobmsg_get_u32(tb[BOOST_BEGIN]);
        if (begin < 0)
        {
            return UBUS_STATUS_INVALID_ARGUMENT;
        }

        begin *= 1000;
    }	

    probe_data.boost_timeout = interval;
    probe_data.boost_count = count;
    probe_data.boost_specified = begin;

    if (probe_data.timeout.pending)
    {
        if (begin > 0)
        {
            probe_data.boost_specified = 0;
            uloop_timeout_set(&probe_data.timeout, begin);
        }
        else
        {
#if HAVE_ULOOP_TIMEOUT_REMAINING64
            int remain = uloop_timeout_remaining64(&probe_data.timeout);
#else
            int remain = uloop_timeout_remaining(&probe_data.timeout);
#endif
            if (remain > interval)
            {
            	uloop_timeout_set(&probe_data.timeout, interval);
            }
        }
    }

    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "success", 0);
    ubus_send_reply(ctx, req, b.head);
    return 0;
}

#if CONFIG_IOT_SUPPORT
#define SYNC_PROBE_EMMC_PROG SYNC_SCRIPTS_DIR "/probe_emmc"
#define SYNC_CONFIG_EMMC_PROG SYNC_SCRIPTS_DIR "/sync-config_emmc"
#define SYNC_DEV_LIST_EMMC_FILE "/tmp/sync-server/mesh_dev_list_emmc"

struct probe_emmc_data
{
    struct uloop_process probe_proc;
    struct uloop_process config_proc;
    struct uloop_timeout timeout;
    int boost_count;
    int boost_timeout;
    char infile[PATH_MAX];
    char outfile[PATH_MAX];
    bool busy;
};
static struct probe_emmc_data probe_emmc_data;
static json_object *devlist_emmc = NULL;

static void
probe_emmc_done(bool success)
{
    int timeout = 0;
	
    probe_emmc_data.busy = false;

    if (probe_emmc_data.boost_count > 0)
    {
        if (success)
        {
            probe_emmc_data.boost_count--;
        }
        timeout = probe_emmc_data.boost_timeout;
    }
    else
    {
        timeout = PROBE_DEFAULT_TIMEOUT;
    }

    uloop_timeout_set(&probe_emmc_data.timeout, timeout);
}

static int
probe_emmc(const char **err)
{
    if (probe_emmc_data.busy)
    {
        LOG("probe process is running");
        *err = "running";
        return -1;
    }

    probe_emmc_data.busy = true;
    snprintf(probe_emmc_data.outfile, PATH_MAX, "%s/probe_emmc-output-%u-%u",
             SYNC_RUNTIME_DIR, (unsigned int)time(NULL), (unsigned int)pid);
    if (NULL == devlist_emmc)
    {
        snprintf(probe_emmc_data.infile, PATH_MAX, "-");
    }
    else
    {
        snprintf(probe_emmc_data.infile, PATH_MAX, "%s/probe_emmc-input-%u-%u",
                 SYNC_RUNTIME_DIR, (unsigned int)time(NULL), (unsigned int)pid);
        if (json_object_to_file(probe_emmc_data.infile, devlist_emmc) < 0)
        {
            LOG("Failed to write devlist to input file");
            *err = "input";
            goto error;
        }
    }

    {
        const char *argv[] = {
            SYNC_PROBE_EMMC_PROG,
            probe_emmc_data.infile, probe_emmc_data.outfile, NULL
        };
        if (add_process(&probe_emmc_data.probe_proc, argv) < 0)
        {
            LOG("Failed to launch process for probing");
            *err = "process";
            goto error;
        }
    }

    return 0;
error:
    probe_emmc_done(false);
    return -1;
}

static void
probe_emmc_timeout_cb(struct uloop_timeout *timeout)
{
    probe_emmc(NULL);
}

static int
handle_boost_emmc(struct ubus_context *ctx, struct ubus_object *obj,
             struct ubus_request_data *req, const char *method,
             struct blob_attr *msg)
{
    struct blob_attr *tb[__BOOST_MAX];
    int count = PROBE_DEFAULT_BOOST_COUNT;
    int interval = PROBE_DEFAULT_BOOST_TIMEOUT;
    int rc = blobmsg_parse(boost_policy, __BOOST_MAX, tb, blob_data(msg), blob_len(msg));
    if (rc < 0)
    {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

    if (tb[BOOST_COUNT])
    {
        count = blobmsg_get_u32(tb[BOOST_COUNT]);
    }

    if (tb[BOOST_INTERVAL])
    {
        interval = blobmsg_get_u32(tb[BOOST_INTERVAL]);
        if (interval <= 0)
        {
            return UBUS_STATUS_INVALID_ARGUMENT;
        }

        interval *= 1000;
    }

    probe_emmc_data.boost_timeout = interval;
    probe_emmc_data.boost_count = count;

    if (probe_emmc_data.timeout.pending)
    {
#if HAVE_ULOOP_TIMEOUT_REMAINING64
        int remain = uloop_timeout_remaining64(&probe_emmc_data.timeout);
#else
        int remain = uloop_timeout_remaining(&probe_emmc_data.timeout);
#endif
        if (remain > interval)
        {
            uloop_timeout_set(&probe_emmc_data.timeout, interval);
        }
    }

    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "success", 0);
    ubus_send_reply(ctx, req, b.head);
    return 0;
}

static int
handle_probe_emmc(struct ubus_context *ctx, struct ubus_object *obj,
             struct ubus_request_data *req, const char *method,
             struct blob_attr *msg)
{
    const char *err;
    int rc;

    uloop_timeout_cancel(&probe_emmc_data.timeout);
	
    rc = probe_emmc(&err);

    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "success", rc);
    if (rc < 0)
    {
        blobmsg_add_string(&b, "errmsg", err);
    }
    ubus_send_reply(ctx, req, b.head);
    return 0;
}

static void
probe_emmc_proc_cb(struct uloop_process *proc, int ret)
{
    int rc;
    struct json_object *root = NULL;
    bool succ = false;

    if (check_proc_ret("probe_emmc", ret))
    {
        struct json_object *success, *errmsg;
        root = json_object_from_file(probe_emmc_data.outfile);
        if (NULL == root)
        {
            LOG("Failed to read json file");
            goto done;
        }

        success = json_object_object_get(root, "success");
        if (json_object_get_int(success) < 0)
        {
            errmsg = json_object_object_get(root, "errmsg");
            LOG("Failed to probe: %s",
                errmsg == NULL ? "unknown error" : json_object_get_string(errmsg));
            goto done;
        }

        if (devlist_emmc != NULL)
        {
            rc = json_object_put(devlist_emmc);
            assert(rc == 1);
        }

        devlist_emmc = json_object_object_get(root, "data");
        if (NULL == devlist_emmc)
        {
            goto done;
        }

        if (json_object_is_type(devlist_emmc, json_type_object))
        {
            struct json_object *to_update_emmc;
            int i;

            json_object_get(devlist_emmc);

            if (myid)
            {
                mydev = json_object_object_get(devlist_emmc, myid);
                if (mydev)
                {
                    json_object_object_add(mydev, "myself", json_object_new_boolean(true));
                }
                else
                {
                    LOG("WARNING: probe failed to find myself");
                }
            }

            to_update_emmc = json_object_object_get(root, "to_update_emmc");
            if (to_update_emmc && json_object_is_type(to_update_emmc, json_type_array))
            {
                const char *argv[SYNC_MAX_DEVICES*2+2] = {SYNC_CONFIG_EMMC_PROG};
                const char **ip_list = &argv[1];
				char bind_state[SYNC_MAX_DEVICES][8];

                int count = json_object_array_length(to_update_emmc);
                if (count > SYNC_MAX_DEVICES)
                {
                    count = SYNC_MAX_DEVICES;
                }

                for (i = 0; i < count; i++)
                {
                    struct json_object *tmp = json_object_array_get_idx(to_update_emmc, i);
                    if (NULL == tmp)
                    {
                        break;
                    }
					snprintf(bind_state[i], sizeof(bind_state[i]), "1");
                    ip_list[i*2] = json_object_get_string(tmp);
					ip_list[i*2+1] = bind_state[i];  
                }

                if (i > 0)
                {
                    ip_list[i*2] = NULL;
                    if (add_process(&probe_emmc_data.config_proc, argv) < 0)
                    {
                        LOG("Failed to launch process for sync");
                        goto done;
                    }
                    goto done_still_busy;
                }
            }

        }
        else
        {
            devlist_emmc = NULL;
        }
        succ = true;
    }

done:
    probe_emmc_done(succ);

done_still_busy:
    if (NULL != root)
    {
        rc = json_object_put(root);
        assert(rc == 1);
    }

    if (strcmp(probe_emmc_data.infile, "-") != 0)
    {
        unlink(probe_emmc_data.infile);
    }
    if(NULL != devlist_emmc)
    {
        if (json_object_to_file(SYNC_DEV_LIST_EMMC_FILE, devlist_emmc) < 0)
        {
            LOG("Failed to write devlist to %s", SYNC_DEV_LIST_EMMC_FILE);
        }
    }
    unlink(probe_emmc_data.outfile);
}

static void
sync_config_emmc_proc_cb(struct uloop_process *proc, int ret)
{
    probe_emmc_done(check_proc_ret("sync-config_emmc", ret));
}

#endif

enum
{
    __LIST_MAX,
};

static const struct blobmsg_policy list_policy[__LIST_MAX] = {
};

static int
handle_list(struct ubus_context *ctx, struct ubus_object *obj,
            struct ubus_request_data *req, const char *method,
            struct blob_attr *msg)
{
    blob_buf_init(&b, 0);
    if (devlist)
    {
        blobmsg_add_object(&b, devlist);
    }
    ubus_send_reply(ctx, req, b.head);
    return 0;
}

enum
{
    DEVICE_HANDLE_TYPE,
    DEVICE_HANDLE_ID,
    DEVICE_DATA,
    __DEVICE_MAX,
};

static const struct blobmsg_policy device_policy[__DEVICE_MAX] = {
    [DEVICE_HANDLE_TYPE] = {"handle_type", BLOBMSG_TYPE_STRING},
    [DEVICE_HANDLE_ID] = {"handle_id", BLOBMSG_TYPE_STRING},        
    [DEVICE_DATA] = {"data", BLOBMSG_TYPE_TABLE}, 
};

static int
handle_device(struct ubus_context *ctx, struct ubus_object *obj,
               struct ubus_request_data *req, const char *method,
               struct blob_attr *msg)
{
    struct blob_attr *tb[__REQUEST_MAX];
    int rc;

    rc = blobmsg_parse(device_policy, __DEVICE_MAX, tb, blob_data(msg), blob_len(msg));
    if (rc < 0)
    {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

    if (!tb[DEVICE_HANDLE_TYPE] || !(tb[DEVICE_HANDLE_ID]))
    {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

    if (!devlist)
    {
        goto done;
    }

    const char *handle_type = blobmsg_get_string(tb[DEVICE_HANDLE_TYPE]);
    const char *handle_id = blobmsg_get_string(tb[DEVICE_HANDLE_ID]);
    struct json_object *old_dev = json_object_object_get(devlist, handle_id);    
    if (strcmp(handle_type, "add") == 0)
    {
        if (old_dev)
        {
            goto done;
        }

        if (!(tb[DEVICE_DATA]))
        {
            return UBUS_STATUS_INVALID_ARGUMENT;
        } 
        
        char *s = blobmsg_format_json(tb[DEVICE_DATA], true);
        if (!s)
        {
            goto done;
        }
        
        struct json_object *new_dev = json_tokener_parse(s);
        free(s);
        if (!new_dev)
        {
            goto done;
        }

        json_object_object_add(devlist, handle_id, new_dev);

        blob_buf_init(&b, 0);
        blobmsg_add_object(&b, devlist);
        ubus_send_reply(ctx, req, b.head);       
    }
    else if (strcmp(handle_type, "del") == 0)
    {
        if (!old_dev)
        {
            goto done;
        }

        const char *argv_del_info[SYNC_MAX_DEVICES+2] = {SYNC_DELETE_INFO_PROG, handle_id, NULL};
        if (add_process(&probe_data.delete_info_proc, argv_del_info) < 0)
        {
            LOG("Failed to launch process for delete_info");
            goto done;
        }
                
        json_object_object_del(devlist, handle_id);
        json_object_put(old_dev);               
    }
    else if (strcmp(handle_type, "add_extended_attr") == 0)
    {
        if (!old_dev)
        {
            goto done;
        }
        if (!(tb[DEVICE_DATA]))
        {
            return UBUS_STATUS_INVALID_ARGUMENT;
        } 

        char *s = blobmsg_format_json(tb[DEVICE_DATA], true);
        if (!s)
        {
            goto done;
        }
        LOG("DEVICE_DATA:s = %s",s);

        struct json_object *extended_attr = json_tokener_parse(s);
        free(s);
        if (!extended_attr)
        {
            goto done;
        }
        struct json_object *to_add_extended_attr = json_object_object_get(devlist, handle_id);
        json_object_object_add(to_add_extended_attr, "extended_attr", extended_attr);

        blob_buf_init(&b, 0);
        blobmsg_add_object(&b, devlist);
        ubus_send_reply(ctx, req, b.head);
    }
    else if (strcmp(handle_type, "update") == 0)
    {
        if (!old_dev)
        {
            goto done;
        }
        if (!(tb[DEVICE_DATA]))
        {
            return UBUS_STATUS_INVALID_ARGUMENT;
        } 
        
        char *s = blobmsg_format_json(tb[DEVICE_DATA], true);
        if (!s)
        {
            goto done;
        }
        
        struct json_object *new_dev_info = json_tokener_parse(s);
        free(s);
        if (!new_dev_info)
        {
            goto done;
        }
        //if dev and attr exist, update it
        json_object_object_foreach(new_dev_info, key, value)
        {
            if (json_object_object_get(old_dev, key))
            {
                struct json_object *new_value = NULL;
                if (json_object_is_type(json_object_object_get(old_dev, key), json_type_string)
                    && json_object_is_type(value, json_type_string))
                {
                    const char* value_str = json_object_get_string(value);
                    new_value = json_object_new_string(value_str);
                }
                else if (json_object_is_type(json_object_object_get(old_dev, key), json_type_int)
                    && json_object_is_type(value, json_type_int))
                {
                    int value_int = json_object_get_int(value);
                    new_value = json_object_new_int(value_int);
                }
                else if (json_object_is_type(json_object_object_get(old_dev, key), json_type_boolean)
                    && json_object_is_type(value, json_type_boolean))
                {
                    bool value_bool = json_object_get_boolean(value);
                    new_value = json_object_new_boolean(value_bool);
                }
                if (new_value != NULL)
                json_object_object_add(old_dev, key, new_value);
            }
        }
        json_object_put(new_dev_info);
    }
    else if (strcmp(handle_type, "simple_remove") == 0)
    {
        if (!old_dev)
        {
            goto done;
        }

        json_object_object_del(devlist, handle_id);
        json_object_put(old_dev);
    }
    else
    {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

    probe_data.dirty = true; 
    
    if(NULL != devlist)
    {
        output_devlist();        
    }

done:
    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "success", 0);
    blobmsg_add_u32(&b, "total", 0);
    ubus_send_reply(ctx, req, b.head);
    return 0;
}


enum
{
    STATUS_ID,
    __STATUS_MAX,
};

static const struct blobmsg_policy status_policy[__STATUS_MAX] = {
    [STATUS_ID] = {"id", BLOBMSG_TYPE_INT32},
};

static int
handle_status(struct ubus_context *ctx, struct ubus_object *obj,
            struct ubus_request_data *req, const char *method,
            struct blob_attr *msg)
{
    struct blob_attr *tb[__STATUS_MAX];
    struct request_data *r = NULL;
    int rc;
    int id;

    rc = blobmsg_parse(status_policy, __STATUS_MAX, tb, blob_data(msg), blob_len(msg));
    if (rc < 0)
    {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

    if (!tb[STATUS_ID])
    {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

    blob_buf_init(&b, 0);

    id = blobmsg_get_u32(tb[STATUS_ID]);
    list_for_each_entry(r, &request_list, list)
    {
        if (r->proc.pid == id)
        {
            blobmsg_add_string(&b, "status", "running");
            ubus_send_reply(ctx, req, b.head);
            return 0;
        }
    }

    blobmsg_add_string(&b, "status", "done");
    ubus_send_reply(ctx, req, b.head);
    return 0;
}

enum
{
    __DEBUG_MAX,
};

static const struct blobmsg_policy debug_policy[__DEBUG_MAX] = {
};

static int
handle_debug(struct ubus_context *ctx, struct ubus_object *obj,
             struct ubus_request_data *req, const char *method,
             struct blob_attr *msg)
{
    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "boost_timeout", probe_data.boost_timeout);
    blobmsg_add_u32(&b, "boost_count", probe_data.boost_count);
#if CONFIG_IOT_SUPPORT
	blobmsg_add_u32(&b, "boost_emmc_timeout", probe_emmc_data.boost_timeout);
	blobmsg_add_u32(&b, "boost_emmc_count", probe_emmc_data.boost_count);
#endif
    ubus_send_reply(ctx, req, b.head);
    return 0;
}

enum
{
    __DETECT_RE_MAX,
};

static const struct blobmsg_policy detect_re_policy[__DETECT_RE_MAX] = {
};

static void
detect_re_done()
{
    int timeout = 0;
	
    detect_re_data.busy = false;
    timeout = DETECT_RE_TIMEOUT;

    uloop_timeout_set(&detect_re_data.timeout, timeout);
}

static int
detect_re(const char **err)
{
	if (detect_re_data.busy)
    {
        LOG("detect_re process is running");
        *err = "running";
        return -1;
    }

	detect_re_data.busy = true;

    {
        const char *argv[] = {
            SYNC_DETECT_RE_PROG, NULL
        };
        if (add_process(&detect_re_data.detect_re_proc, argv) < 0)
        {
            LOG("Failed to launch process for detect");
            *err = "process";
            goto error;
        }
    }

	return 0;
error:
    detect_re_done();
    return -1;
}

static void
detect_re_timeout_cb(struct uloop_timeout *timeout)
{
    detect_re(NULL);
}

static void
detect_re_proc_cb(struct uloop_process *proc, int ret)
{
	detect_re_done();
}

static int
handle_detect_re(struct ubus_context *ctx, struct ubus_object *obj,
             struct ubus_request_data *req, const char *method,
             struct blob_attr *msg)
{
    const char *err;
    int rc;

    uloop_timeout_cancel(&detect_re_data.timeout);
	
    rc = detect_re(&err);

    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "success", rc);
    if (rc < 0)
    {
        blobmsg_add_string(&b, "errmsg", err);
    }
    ubus_send_reply(ctx, req, b.head);
    return 0;
}

enum
{
    GET_INFO_IP,
    __GET_INFO_MAX,
};

static const struct blobmsg_policy get_info_policy[__GET_INFO_MAX] = {
	[GET_INFO_IP] = {"ip", BLOBMSG_TYPE_ARRAY},
};


static void
get_info_proc_direct_cb(struct uloop_process *proc, int ret)
{
}

static int
handle_get_info(struct ubus_context *ctx, struct ubus_object *obj,
             struct ubus_request_data *req, const char *method,
             struct blob_attr *msg)
{
	const char *err;
	struct blob_attr *tb[__GET_INFO_MAX];
	int rc;
	rc = blobmsg_parse(get_info_policy, __GET_INFO_MAX, tb, blob_data(msg), blob_len(msg));
    if (rc < 0)
    {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

    if (!tb[GET_INFO_IP])
    {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

	char *s = blobmsg_format_json(tb[GET_INFO_IP], true);
	if (!s)
	{
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	struct json_object *to_get_info = json_tokener_parse(s);

	if (to_get_info && json_object_is_type(to_get_info, json_type_array))
	{
		const char *argv_info[SYNC_MAX_DEVICES*2+2] = {SYNC_GET_INFO_PROG};
		const char **ip_list_info = &argv_info[1];
		int i;
		int count_info = json_object_array_length(to_get_info);
		if (count_info > SYNC_MAX_DEVICES)
		{
			count_info = SYNC_MAX_DEVICES;
		}
		for (i = 0; i < count_info; i++)
		{
			struct json_object *tmp_info = json_object_array_get_idx(to_get_info, i);
			if (NULL == tmp_info)
			{
				break;
			}
			ip_list_info[2 * i] = json_object_get_string(tmp_info);
			ip_list_info[2 * i + 1] = "1";
		}
		if (i > 0)
		{
			ip_list_info[2 * i] = NULL;
			if (add_process(&get_info_data.get_info_proc, argv_info) < 0)
			{
				LOG("Failed to launch process for get_info");
				err = "process";
				rc = -1;
			}
		}
	}

    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "success", rc);
    if (rc < 0)
    {
        blobmsg_add_string(&b, "errmsg", err);
    }
    ubus_send_reply(ctx, req, b.head);
    return UBUS_STATUS_OK;
};


enum {
    __FORCE_SYNC_MAX,
};

static const struct blobmsg_policy force_sync_policy[__FORCE_SYNC_MAX] = {
};

static void
force_sync_proc_cb(struct uloop_process *proc, int ret)
{
    struct force_sync_data *r = container_of(proc, struct force_sync_data, proc);
    bool success = check_proc_ret("force-sync", ret);

    if (success)
    {
	    blob_buf_init(&b, 0);
	    blobmsg_add_u32(&b, "success", 0);
	    ubus_send_reply(ctx, &r->req, b.head);
    }
    else
    {
        char msg[64];
        if (WIFSIGNALED(ret))
        {
            snprintf(msg, 64, "process was killed by signal %d", WTERMSIG(ret));
        }
        else
        {
            snprintf(msg, 64, "process exited with code %d", WEXITSTATUS(ret));
        }
        reply_error(ctx, &r->req, msg);
    }
    ubus_complete_deferred_request(ctx, &r->req, 0);
	probe_data.update_dirty = false;
    free(r);
}

static int
handle_force_sync(struct ubus_context *ctx, struct ubus_object *obj,
             struct ubus_request_data *req, const char *method,
             struct blob_attr *msg)
{
    struct force_sync_data *r = malloc(sizeof(struct force_sync_data));
    if (r == NULL)
    {
        return reply_error(ctx, req, "memory");
    }
    memset(r, 0, sizeof(struct force_sync_data));
	r->proc.cb = force_sync_proc_cb;

	probe_data.update_dirty = true;

    {
        const char *argv[] = {
            SYNC_FORCE_SYNC_PROG, NULL
        };
        if (add_process(&r->proc, argv) < 0)
        {
            LOG("Failed to launch process for force_sync");
            free(r);
            return reply_error(ctx, req, "process");
        }
    }

	ubus_defer_request(ctx, req, &r->req);

    return 0;
}

static const struct ubus_method sync_methods[] = {
    UBUS_METHOD("request", handle_request, request_policy),
    UBUS_METHOD("send", handle_request, request_policy),
    UBUS_METHOD("probe", handle_probe, probe_policy),
    UBUS_METHOD("boost", handle_boost, boost_policy),
    UBUS_METHOD("list", handle_list, list_policy),
    UBUS_METHOD("device", handle_device, device_policy),   
    UBUS_METHOD("status", handle_status, status_policy),
    UBUS_METHOD("debug", handle_debug, debug_policy),
    UBUS_METHOD("detect_re", handle_detect_re, detect_re_policy),
    UBUS_METHOD("get_info", handle_get_info, get_info_policy),
    UBUS_METHOD("force_sync", handle_force_sync, force_sync_policy),
#if CONFIG_IOT_SUPPORT
	UBUS_METHOD("probe_emmc", handle_probe_emmc, probe_policy),
	UBUS_METHOD("boost_emmc", handle_boost_emmc, boost_policy),
#endif
};

static struct ubus_object_type sync_obj_type =
    UBUS_OBJECT_TYPE(SYNC_OBJ_NAME, sync_methods);

static struct ubus_object sync_obj = {
    .name = SYNC_OBJ_NAME,
    .type = &sync_obj_type,
    .methods = sync_methods,
    .n_methods = ARRAY_SIZE(sync_methods),
};

static void
server_main(void)
{
    int rc;

    rc = ubus_add_object(ctx, &sync_obj);
    if (rc < 0)
    {
        LOG("Failed to add object: %s", ubus_strerror(rc));
    }

    uloop_run();
}

static void
get_device_id(void)
{
    char buf[64];
    size_t len;
    FILE *fp = popen("getfirm DEV_ID", "r");
    if (NULL == fp)
    {
        LOG("Failed to call getfirm");
        return;
    }

    if (fgets(buf, 64, fp) == NULL)
    {
        LOG("Failed to read device id");
        goto done;
    }

    len = strlen(buf);
    if (buf[len-1] == '\n')
    {
        buf[--len] = '\0';
    }

    myid = strdup(buf);

    LOG("Device ID: %s", buf);
    /* TODO: magic number here */
    if (len != 40)
    {
        LOG("WARNING: the length of device id is illegal");
    }

done:
    pclose(fp);
}

int
main (int argc, char *argv[])
{
    pid = getpid();
    mkdir(SYNC_RUNTIME_DIR, 0755);
    get_device_id();

    memset(&probe_data, 0, sizeof(struct probe_data));
    probe_data.probe_proc.cb = probe_proc_cb;
    probe_data.config_proc.cb = sync_config_proc_cb;
	probe_data.get_info_proc.cb = get_info_proc_cb;
	probe_data.delete_info_proc.cb = delete_info_proc_cb;
    
    probe_data.timeout.cb = probe_timeout_cb;
    probe_data.boost_count = PROBE_DEFAULT_BOOST_COUNT;
    probe_data.boost_timeout = PROBE_DEFAULT_BOOST_TIMEOUT;
	probe_data.update_dirty = false;
    probe(NULL);

#if CONFIG_IOT_SUPPORT
	memset(&probe_emmc_data, 0, sizeof(struct probe_emmc_data));
	probe_emmc_data.probe_proc.cb = probe_emmc_proc_cb;
	probe_emmc_data.config_proc.cb = sync_config_emmc_proc_cb;
    probe_emmc_data.timeout.cb = probe_emmc_timeout_cb;
    probe_emmc_data.boost_count = PROBE_DEFAULT_BOOST_COUNT;
    probe_emmc_data.boost_timeout = PROBE_DEFAULT_BOOST_TIMEOUT;
	probe_emmc(NULL);
#endif

    memset(&detect_re_data, 0, sizeof(struct detect_re_data));
    detect_re_data.detect_re_proc.cb = detect_re_proc_cb;
    detect_re_data.timeout.cb = detect_re_timeout_cb;
    detect_re_data.detect_re_timeout = DETECT_RE_TIMEOUT;
    detect_re(NULL);

	memset(&get_info_data, 0, sizeof(struct get_info_data));
	get_info_data.get_info_proc.cb = get_info_proc_direct_cb;

    uloop_init();
    signal(SIGPIPE, SIG_IGN);

    ctx = ubus_connect(NULL);
    if (!ctx)
    {
        LOG("Failed to connect to ubus");
        return 1;
    }

    ubus_add_uloop(ctx);

    server_main();

    ubus_free(ctx);
    uloop_done();

    return 0;
}
