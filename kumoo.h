/************************************
 * Created by Hoeun Lee on 5/2/24.
 * Operating System
 * Konkuk University Dept. of C.S.E.
 * Hoeun Lee 202011353
 ************************************/

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

// ============================================================
#define ADDR_SIZE 16

#define PAGE_SIZE 64 // 64B

#define PCB_LIST_LENGTH 1 << 4
#define PF_QUEUE_LENGTH 4096
#define READY_QUEUE_LENGTH 1 << 4

// ============================================================
/** Constants for Free Block types */
#define FB_TYPE_PAGE_DIR 1
#define FB_TYPE_PAGE_TBL 2
#define FB_TYPE_PAGE 3

// ============================================================
/** Global Variables */
struct pcb *current; // PCB of Current Running Process
unsigned short *pdbr; // Page Directory Base Register
char *pmem; // Physical Memory Base Address (on RAM)
char *swaps; // Swap Space Base Address (on Disk)
int pfnum; // Number of Page Frames on Physical Memory
int sfnum; // Number of Page Frames on Swap Space

struct free_block **free_pf_list; // physical memory free list
struct free_block **free_sf_list; // swap space free list

struct pcb **pcb_list; // PCB Address List (Array)
struct queue *pf_queue; // Page Frame Queue (for Page Replacement)
struct queue *ready_queue; // Process Ready Queue

/** Dump Functions in kumoo.c */
void ku_dump_pmem(void);
void ku_dump_swap(void);

// ============================================================
/** Struct of Free Block in Free List */
struct free_block {
    int type; // 1: Page Directory, 2: Page Table, 3: Page
    unsigned short pid; // Process ID
    int back_pfn; // Inverse Pointer to Page Table or Page Directory. 0 ~ positive for PFN, negative for SFN
};

// ===========================================================
/** Struct PCB */
struct pcb {
    unsigned short pid; // Process ID
    FILE *fd; // File Descriptor
    unsigned short *pgdir; // Page Directory Address
    unsigned short pd_pfn;

    /* Add more fields as needed */
    int vbase; // Virtual Address Space Base Address
    int vlength; // Virtual Address Space Length
};

// ============================================================
/** Calculate Physical Memory Usage (Percent) */
double pmem_usage() {
    int proc_usage[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    int count = 0;
    for (int i = 0; i < pfnum; i++) {
        if (free_pf_list[i] != NULL) {
            count++;
            proc_usage[free_pf_list[i]->pid]++;
        }
    }

    double usage = (double)count / (double)pfnum * 100.0;
    printf("*** PMEM Usage: %d/%d (%f%%) ***\n", count, pfnum, usage);
    printf("000 001 002 003 004 005 006 007 008 009\n");
    for (int i = 0; i < 10; i++) {
        printf("%3d ", proc_usage[i]);
    }
    printf("\n");
    return usage;
}

/** Calculate Swap Space Usage (Percent) */
double swap_usage() {
    int proc_usage[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    int count = 0;
    for (int i = 0; i < sfnum; i++) {
        if (free_sf_list[i] != NULL) {
            count++;
            proc_usage[free_sf_list[i]->pid]++;
        }
    }

    double usage = (double)count / (double)sfnum * 100.0;
    printf("*** SWAP Usage: %d/%d (%f%%) ***\n", count, sfnum, usage);
    printf("000 001 002 003 004 005 006 007 008 009\n");
    for (int i = 0; i < 10; i++) {
        printf("%3d ", proc_usage[i]);
    }
    printf("\n");
    return usage;
}

// ============================================================
/** Inode Queue implemented by Array (for Page Frame List, Swap Candidates) */
struct queue {
    unsigned short *data;
    int front;
    int rear;
    int length;
    int max_length;
};

/** Initialize a Queue */
void queue_init(struct queue **_queue, int max_length) {
    *_queue = malloc(sizeof(struct queue));
    (*_queue)->data = (unsigned short*)malloc(sizeof(unsigned short) * max_length);
    (*_queue)->front = -1;
    (*_queue)->rear = -1;
    (*_queue)->length = 0;
    (*_queue)->max_length = max_length;
}

/** Check the Queue is Empty */
int queue_check_empty(const struct queue *_queue) {
    return (_queue->front == -1);
}

/** Check the Queue is Full */
int queue_check_full(const struct queue *_queue) {
    return ((_queue->rear + 1) % _queue->max_length == _queue->front);
}

/** Get current Length of the Queue*/
int queue_length(const struct queue *_queue) {
    return _queue->length;
}

/** Enqueue an Item to the Queue */
void enqueue(struct queue **_queue, unsigned short item) {
    if (queue_check_full((*_queue))) {
        // printf("  [OS] INFO: Queue is Full, Cannot Enqueue.\n");
        return;
    }

    (*_queue)->rear = ((*_queue)->rear + 1) % (*_queue)->max_length;
    (*_queue)->data[(*_queue)->rear] = item;

    if ((*_queue)->front == -1) {
        (*_queue)->front = (*_queue)->rear;
    }

    (*_queue)->length++;
}

/** Delete (Dequeue) an Item from the Queue */
unsigned short dequeue(struct queue **_queue) {
    unsigned short item;

    if (queue_check_empty((*_queue))) {
        // printf("  [OS] INFO: Queue is Empty, Cannot Dequeue.\n");
        return -1;
    }

    item = (*_queue)->data[(*_queue)->front];
    if ((*_queue)->front == (*_queue)->rear) {
        (*_queue)->front = (*_queue)->rear = -1;
    } else {
        (*_queue)->front = ((*_queue)->front + 1) % (*_queue)->max_length;
    }

    (*_queue)->length--;
    return item;
}

/** Print Inode Queue */
void queue_print(const struct queue *_queue) {
    for (int i = 0; i < _queue->max_length; i++) {
        printf("%hu ", _queue->data[i]);
    }
    printf("\n");
    for (int i = 0; i < _queue->max_length; i++) {
        if (i == _queue->front) {
            printf("f ");
        } else if (i == _queue->rear) {
            printf("r ");
        } else {
            printf("  ");
        }
    }
    printf("\n");
}

// ============================================================
/** Print PCB Information */
void print_pcb(struct pcb *_target) {
    printf("addr: %p\n", _target);
    printf("vbase: %d\n", _target->vbase);
    printf("vlength: %d\n", _target->vlength);
    printf("pdir addr: (%p)(pfn: %hu)\n", _target->pgdir, _target->pd_pfn);
}

/** Print PCB as a List */
void print_pcb_list() {
    for (int i = 0; i < PCB_LIST_LENGTH; i++) {
        if (pcb_list[i] != NULL) {
            printf("----- PCB (%hu) -----\n", pcb_list[i]->pid);
            print_pcb(pcb_list[i]);
        }
    }
    printf("--------------------\n");
}

// ============================================================
/** Entry Manipulation Functions */
int check_entry_valid(const unsigned short entry) {
    // valid 1 (true), invalid 0 (false)
    return entry != 0;
}

int check_entry_invalid(const unsigned short entry) {
    // valid 0 (false), invalid 1 (true)
    return entry == 0;
}

/** Check is Dirty Bit Set */
int check_entry_dirty(const unsigned short entry) {
    return (entry & 0x2) >> 1;
}

/** Check the Present Bit is Set */
int check_entry_present(const unsigned short entry) {
    return (entry & 0x1);
}

/** Check the Entry is Swapped-Out */
int check_entry_swapped(const unsigned short entry) {
    // dirty 1, present 0
    return (((entry & 0x2) >> 1) == 1) && ((entry & 0x1) == 0);
}

/** Get Page Frame Number (PFN) from Entry */
int get_pfn_from_entry(const unsigned short entry) {
    // Get PFN at Entry (top 12-Bit)
    // int pfn = (PFN_MASK & entry) >> PFN_SHIFT;
    int pfn = (entry & 0xFFF0) >> 4;
    return pfn;
}

/** Get Swap Space Page Frame Number (SFN) from Entry */
int get_sfn_from_entry(const unsigned short entry) {
    // Get Swap PFN at Entry (top 14-Bit)
    // int sfn = (SWAP_MASK & entry) >> SWAP_SHIFT;
    int sfn = (entry & 0xFFFC) >> 2;
    return sfn;
}

/** Get Page Frame (64-Byte) Address from Physical Memory */
// PFN -> Addr (on Physical Memory)
char* get_pf_addr(const int pfn) {
    return (pmem + (pfn << 6));
}

/** Get Page Frame (64-Byte) Address from Swap Space */
char* get_sf_addr(const int sfn) {
    return (swaps + (sfn << 6));
}

// ============================================================
/** Print Page Table or Directory Entry Bit by Bit */
void print_entry(const unsigned short entry) {
    for (int i = 0; i < ADDR_SIZE; i++) {
        printf("%x ", ((entry << i) & 0x8000) >> 15);
    }
}

// ============================================================
/** Get Next Free SF Number by Sequential Algorithm */
int get_sfn_sequential(int not_sfn) {
    // Find Free SFN Index
    // swap space index 는 1부터 시작
    for (int sfn = 1; sfn < sfnum; sfn++) {
        if (free_sf_list[sfn] == NULL && sfn != not_sfn) {
            return sfn;
        }
    }

    // printf("[OS] FETAL ERROR: Swap Space is Full.\n");
    return -1;
}

unsigned short *find_entry_by_pfn(unsigned short pfn, unsigned short pfn_to_find) {
    unsigned short *pgbr = (unsigned short*)(pmem + (pfn << 6));

    for (int i = 0; i < (1 << 5); i++) {
        unsigned short *entry = pgbr + i;
        int target_pfn = (*entry & 0xFFF0) >> 4;

        if (target_pfn == pfn_to_find) {
            return entry;
        }
    }

    // cannot find
    // printf("  [OS] FETAL ERROR: Cannot Find PFN in PFN TO FIND\n");
    return NULL;
}

/** Get Next Free PF Number by Sequential Algorithm
 *  If there is no space in physical memory, swapping */
int get_pfn_sequential(int not_evict_pfn) {
    // printf("===== [OS] get_pfn_sequential is called =====\n");
    // Find Free PFN Index
    for (int pfn = 0; pfn < pfnum; pfn++) {
        if (free_pf_list[pfn] == NULL && pfn != not_evict_pfn) {
            // found a free pfn
            return pfn;
        }
    }

    // There is no free PFN, Swapping is needed
    // printf("[OS] INFO: No Free PFN Found, Swapping.\n");
    // pmem_usage();

    int pfn_to_evict;
    int pt_flag;
    int pte_all_invalid;
    int pte_all_swap_out;
    int pfn_found = 0;

    // Find pfn to evict
    if (queue_check_empty(pf_queue)) {
        // pf queue is empty
        return -1;
    }

    for (int j = 0; j < pf_queue->length; j++) {
        pfn_to_evict = dequeue(&pf_queue);

        if (pfn_to_evict == not_evict_pfn) {
            enqueue(&pf_queue, pfn_to_evict);
            continue;
        }

        if (free_pf_list[pfn_to_evict] == NULL) {
            enqueue(&pf_queue, pfn_to_evict);
            continue;
        }

        pte_all_invalid = 0;
        pte_all_swap_out = 0;

        if (free_pf_list[pfn_to_evict]->type == FB_TYPE_PAGE_TBL) {
            // printf("  [OS] INFO: pfn_to_evict(%d) Page is Page Table, check can be evicted.\n", pfn_to_evict);

            // check all page table entry is invalid or swapped-out
            unsigned short *pfn_to_evict_addr = (unsigned short*)(pmem + (pfn_to_evict << 6));

            // reset flag
            pt_flag = 0;

            // All Page Table Entry is Invalid
            for (int i = 0; i < (1 << 5); i++) {
                unsigned short *entry = pfn_to_evict_addr + i;
                if (check_entry_valid(*entry)) {
                    pt_flag = 1;
                    // printf("  [OS] INFO: pfn_to_evict(%d) has one or more validate entry, cannot be evicted.\n", pfn_to_evict);
                    break;
                }
            }
            // all pte is invalid
            if (pt_flag == 0) {
                pte_all_invalid = 1;
            }

            // reset flag
            pt_flag = 0;

            // All Page Table Entry is Swapped-Out
            if (pte_all_invalid == 0) {
                for (int i = 0; i < (1 << 5); i++) {
                    unsigned short *entry = pfn_to_evict_addr + i;
                    // 해당 페이지가 valid 한데, swapped-out 상태인지 검사
                    // 즉 present한 entry가 하나라도 있다면 evict가 불가능
                    if (check_entry_present(*entry)) {
                        pt_flag = 1;
                        // printf("  [OS] INFO: pfn_to_evict(%d) has one or more presenting entry, cannot be evicted.\n", pfn_to_evict);
                        break;
                    }
                }

                // all pte is present
                if (pt_flag == 0) {
                    pte_all_swap_out = 1;
                }
            }

            // printf("  pte_all_invalid: (%d) / pte_all_swap_out: (%d)\n", pte_all_invalid, pte_all_swap_out);

            // cannot be evicted
            if (pte_all_invalid == 0 && pte_all_swap_out == 0) {
                // printf("  [OS] INFO: This Page Table PFN cannot be evicted, try another new PFN.\n  ------\n");
                enqueue(&pf_queue, pfn_to_evict);
                continue;
            }
            // pt_flag == 0 (can be evicted)
            else {
                // printf("  [OS] INFO: pfn_to_evict(%d) Page is Page Table, but can be evicted.\n", pfn_to_evict);
                pfn_found = 1;
                break;
            }
        }
        // Page Frame
        else if (free_pf_list[pfn_to_evict]->type == FB_TYPE_PAGE) {
            // printf("  [OS] INFO: pfn_to_evict(%d) Page is Page Frame, can be evicted.\n", pfn_to_evict);
            pfn_found = 1;
            break;
        }
        // Page Directory (Exception)
        else {
            // Cannot be reached
            // printf("  [OS] ERROR: pfn_to_evict is Page Directory.\n");
            // printf("===== [OS] get_pfn_sequential is returned (-1) =====\n");
            // enqueue(&pf_queue, pfn_to_evict);
            continue;
        }
    }

    printf("pfn found: %d, pfn_to_evict: %d\n", pfn_found, pfn_to_evict);

    if (pfn_found == 0) {
        return -1;
    }

    // pfn_to_evict is found

    // sfn to swap out
    int sfn = get_sfn_sequential(-1);

    // A. Page Table
    if (free_pf_list[pfn_to_evict]->type == FB_TYPE_PAGE_TBL) {
        // Find Page Directory
        unsigned short pd_pfn = free_pf_list[pfn_to_evict]->back_pfn;

        // Page Directory에서 pfn_to_evict를 가르키는 PD Entry 주소 검색
        unsigned short *pd_entry = find_entry_by_pfn(pd_pfn, pfn_to_evict);
        if (pd_entry == NULL) {
            // printf("  [OS] ERROR: Inverse Pointing Page Directory is NULL (sfn: %hu).\n", pd_pfn);
            return -1;
        }

        // A-1) 이 Page Table의 모든 Entry가 invalid 하다면 빈 페이지 테이블 → 버림
        if (pte_all_invalid == 1) {
            // Page Directory에서 pfn_to_evict 가르키는 PD_Entry를 invalidate로 수정

            // PD Entry invalid 0으로, 설정
            unsigned short new_pd_entry = 0;
            (*pd_entry) = new_pd_entry;

            // 해당 page를 0으로 초기화
            memset(get_pf_addr(pfn_to_evict), 0, (size_t)PAGE_SIZE);

            // Swap Out할 Page Table의 free block 제거
            free(free_pf_list[pfn_to_evict]);
            free_pf_list[pfn_to_evict] = NULL;
        }

        // A-2) 이 Page Table이 가르키는 Page들의 free_block을 수정
        else if (pte_all_swap_out == 1) {
            // free sf list 순차 검색해서 inverse pointer가 이 pfn_to_evict인 페이지를 검색
            for (int i = 0; i < sfnum; i++) {
                if (free_sf_list[i] != NULL && free_sf_list[i]->back_pfn == pfn_to_evict) {
                    // free block의 back_pfn을 -sfn으로 수정 (inverse pointer를 수정)
                    free_sf_list[i]->back_pfn = -sfn; // sfn은 음수
                }
            }

            // 검사 - 있으면 안됨 (오류)
            for (int i = 0; i < pfnum; i++) {
                if (free_pf_list[i] != NULL && free_pf_list[i]->back_pfn == pfn_to_evict) {
                    // printf("  [OS] FETAL ERROR: This Page Table cannot be evicted, some Entry(offset: %d) is Present.\n", i);
                    return -1;
                }
            }

            // Page Directory 수정
            // int lsb = 0b0010; // dirty 1, present 0
            unsigned short new_pd_entry = sfn << 2 | 0x2;
            (*pd_entry) = new_pd_entry;

            // Page를 PMEM -> SWAPS 복사, 해당 Page를 0으로 초기화
            memcpy(get_pf_addr(pfn_to_evict), get_sf_addr(sfn), (size_t)PAGE_SIZE);
            memset(get_pf_addr(pfn_to_evict), 0, (size_t)PAGE_SIZE);

            // Swap Out할 Page Table의 free_block을 free_pf_list → free_sf_list로 이동
            free_sf_list[sfn] = free_pf_list[pfn_to_evict];
            free_pf_list[pfn_to_evict] = NULL;
        }
    }

    // B. Page Frame
    else if (free_pf_list[pfn_to_evict]->type == FB_TYPE_PAGE) {
        // Find Page Table
        unsigned short pt_pfn = free_pf_list[pfn_to_evict]->back_pfn;

        // Page Table 에서 pfn_to_evict를 가르키는 Page Entry 주소 검색
        unsigned short *pt_entry = find_entry_by_pfn(pt_pfn, pfn_to_evict);
        if (pt_entry == NULL) {
            // printf("  [OS] ERROR: Inverse Pointing Page Table is NULL (sfn: %hu).\n", pt_pfn);
            return -1;
        }

        // B-1) 해당 Page를 가르키는 PT Entry가 not dirty라면 → 버림
        if (!check_entry_dirty(*pt_entry)) {
            // 해당 Page를 가르키는 PT Entry를 invalidate (0)으로 수정

            // PT Entry invalid 0으로, 설정
            unsigned short new_pt_entry = 0;
            (*pt_entry) = new_pt_entry;

            // 해당 page를 0으로 초기화
            memset(get_pf_addr(pfn_to_evict), 0, (size_t)PAGE_SIZE);

            // Swap Out할 Page의 free block 제거
            free(free_pf_list[pfn_to_evict]);
            free_pf_list[pfn_to_evict] = NULL;
        }

        // B-2) 해당 Page를 가르키는 PT Entry가 dirty라면 → Swap Out
        else {
            // Page Table Entry 수정
            // int lsb = 0b0010; // dirty 1, present 0
            unsigned short new_pt_entry = sfn << 2 | 0x2;
            (*pt_entry) = new_pt_entry;

            // printf("  *** PT Entry: \n");
            // print_entry(new_pt_entry);
            // printf("\n");

            // Page를 PMEM -> SWAPS 복사, 해당 Page를 0으로 초기화
            memcpy(get_pf_addr(pfn_to_evict), get_sf_addr(sfn), (size_t)PAGE_SIZE);
            memset(get_pf_addr(pfn_to_evict), 0, (size_t)PAGE_SIZE);

            // Swap Out할 Page의 free_block을 free_pf_list → free_sf_list로 이동
            free_sf_list[sfn] = free_pf_list[pfn_to_evict];
            free_pf_list[pfn_to_evict] = NULL;
        }
    }
        // Page Directory (Exception)
    else {
        // Cannot be reached
        // printf("  [OS] ERROR: pfn_to_evict is Page Directory.\n");
        // printf("===== [OS] get_pfn_sequential is returned (-1) =====\n");
        return -1;
    }

    // printf("===== [OS] get_pfn_sequential is returned (%d) =====\n", pfn_to_evict);
    return pfn_to_evict;
}

/** Return a used PFN (free back) */
int return_pfn(unsigned short pfn) {
    if (free_pf_list[pfn] == NULL) {
        // printf("  [OS] ERROR: Segmentation Fault - Try to Free Unallocated Physical Memory (%hu).\n", pfn);
        return 1;
    }

    memset(get_pf_addr(pfn), 0, (size_t)PAGE_SIZE);
    free(free_pf_list[pfn]);
    free_pf_list[pfn] = NULL;

    // printf("  [OS]: Page Frame (%hu) and a Free Block are Unallocated Successfully.\n", pfn);
    return 0;
}

/** Return a used SFN (free back) */
int return_sfn(unsigned short sfn) {
    if (free_sf_list[sfn] == NULL) {
        // printf("  [OS] ERROR: Segmentation Fault - Try to Free Unallocated Swap Space Page (%hu).\n", sfn);
        return 1;
    }

    memset(get_sf_addr(sfn), 0, (size_t)PAGE_SIZE);
    free(free_sf_list[sfn]);
    free_sf_list[sfn] = NULL;

    // printf("  [OS]: Swap Space Frame (%hu) and a Free Block are Unallocated Successfully.\n", sfn);
    return 0;
};


// ============================================================
/** Initialize Free Lists */
void ku_freelist_init() {
    // printf("\n===== [OS] ku_freelist_init() called =====\n");
    free_pf_list = (struct free_block**)malloc(sizeof(struct free_block*) * pfnum);
    free_sf_list = (struct free_block**)malloc(sizeof(struct free_block*) * sfnum);

    // printf("  [OS] free_pf_list initialized at (%p) with length %hu\n", free_pf_list, pfnum);
    // printf("  [OS] free_sf_list initialized at (%p) with length %hu\n", free_sf_list, sfnum);
    // printf("===== [OS] ku_freelist_init() returned =====\n\n");
}


// ============================================================
/** Initialize Processes */
int ku_proc_init(int argc, char *argv[]) {
    // printf("\n===== [OS] ku_proc_init called =====\n");

    FILE *fs; // file descriptor for input txt
    unsigned short pid; // to save pid
    char pf_name[256];

    // Open a File
    fs = fopen(argv[1], "r");

    if (fs == NULL) {
        // printf("  [OS] ERROR: Cannot Open a File (%s)\n", argv[1]);
        // printf("===== [OS] ku_proc_init returned (1) =====\n\n");
        return 1;
    }

    // Initialize PCB List (Double Pointer Array)
    pcb_list = (struct pcb**)malloc(sizeof(struct pcb*) * PCB_LIST_LENGTH);

    // Initialize a Process Ready Queue
    queue_init(&ready_queue, READY_QUEUE_LENGTH);

    // Initialize a PFN Queue (for page frame replacement policy)
    queue_init(&pf_queue, PF_QUEUE_LENGTH);

    // Initialize and Instantiate PCBs for n Processes
    while(fscanf(fs, "%hu %s", &pid, pf_name) != EOF) {
        int vbase, vlength;
        char temp[256];

        // Create a New PCB Instance
        struct pcb *new_pcb = malloc(sizeof(struct pcb));

        // Set PID in PCB
        new_pcb->pid = pid;

        // Enqueue to Ready Queue
        enqueue(&ready_queue, pid);

        // Open Process File and Save File Descriptor in PCB
        new_pcb->fd = fopen(pf_name, "r");

        // Check File is Opened Successfully
        if (new_pcb->fd == NULL) {
            // printf("  [OS] ERROR: Cannot Open a Process txt File (%s)\n", pf_name);
            // printf("===== [OS] ku_proc_init returned (1) =====\n\n");
            return 1;
        }

        // Read the First Line
        // this line must be "d" (data segment header)
        fscanf(new_pcb->fd, "%s", temp);

        // Read vbase and vlength
        fscanf(new_pcb->fd, "%d %d", &vbase, &vlength);

        // set vbase and vlength in pcb
        new_pcb->vbase = vbase;
        new_pcb->vlength = vlength;

        // Initialize Page Directory for a Process
        int pfn = get_pfn_sequential(-1);

        if (pfn < 0) {
            // no free pfn
            return 1;
        }

        // create new free block
        struct free_block *new_free_block = malloc(sizeof(struct free_block));

        new_free_block->pid = pid;
        new_free_block->type = FB_TYPE_PAGE_DIR; // page directory

        // page directory 는 back point 없음
        new_free_block->back_pfn = 0;

        // Get PFN Address on Physical Memory
        char *pd_addr = get_pf_addr(pfn);

        // page directory는 swap out 되지 않으므로 pf_queue에 넣지 않음

        // Allocate Page Directory to PCB
        new_pcb->pgdir = (unsigned short*)pd_addr;
        new_pcb->pd_pfn = pfn;

        free_pf_list[pfn] = new_free_block;

        // printf("  [OS]: pfn(%hu) is allocated to pd of pcb(pid: %hu) at (%p)\n", pfn, pid, pd_addr);

        // Add PCB to PCB List
        pcb_list[pid] = new_pcb;
    }

    // close file descriptor
    fclose(fs);

    // Print PCBs List
    // print_pcb_list();
    // printf("  [OS] %d processes are in a Ready Queue\n", ready_queue->length);

    // printf("===== [OS] ku_proc_init returned (0) =====\n\n");
    return 0;
}


// ============================================================
/** Scheduler Function with Round Robin Policy */
int ku_scheduler(unsigned short pid) {
    // printf("\n===== [OS] ku_scheduler called (pid: %hu) =====\n", pid);

    if (current == NULL && queue_check_empty(ready_queue)) {
        // printf("  [OS] Scheduler: No Process Found\n");
        // printf("===== [OS] ku_scheduler returned (1) =====\n\n");
        return 1;
    }

    // there is a running process but ready queue is empty
    if (queue_check_empty(ready_queue)) {
        // printf("  [OS] Scheduler (pid: %hu) -> (next pid: %hu) Not Changed\n", pid, pid);
        // printf("===== [OS] ku_scheduler returned (0) =====\n\n");
        return 0;
    }

    // Selects the next process in a round-robin manner (starts from PID 0)
    unsigned short next_pid = dequeue(&ready_queue);

    // printf("*** [OS] Scheduler (pid: %hu) -> (next pid: %hu)\n", pid, next_pid);

    // set running process
    current = pcb_list[next_pid];

    // error check
    if (current == NULL) {
        // printf("  [OS] ERROR: Cannot find specific Process, Current Process Pointer is NULL\n");
        // printf("===== [OS] ku_scheduler returned (1) =====\n\n");
        return 1;
    }
    pdbr = current->pgdir;

    // enqueue pid in ready queue
    // pid=10 initialize
    if (pid < 10 && pcb_list[pid] != NULL) {
        // printf("  [OS] Process (%hu) is enqueued to ready queue\n", pid);
        enqueue(&ready_queue, pid);
    } else {
        // printf("  [OS] Process (%hu) is not enqueued because it has been terminated\n", pid);
    }

    // printf("  [OS] Running Process is switched from (%hu) to (%hu)\n", pid, next_pid);
    // printf("  READY QUEUE:\n");
    // queue_print(ready_queue);

    // success 0, error 1 (no processes found)
    // printf("===== [OS] ku_scheduler returned (0) =====\n\n");
    return 0;
}


// ============================================================
/** Page Fault Handler */
int ku_pgfault_handler(unsigned short va) {
    // printf("\n===== [OS] ku_pgfault_handler called (va: %hu) =====\n", va);

    // 1. virtual address 검사
    if (va < current->vbase || va >= (current->vbase + current->vlength)) {
        // printf("  [OS] ERROR: Segmentation Fault, Prohibited Memory Access to (%d) out of address space (%d ~ %d)\n", va, current->vbase, current->vbase + current->vlength - 1);
        // printf("===== [OS] ku_pgfault_handler returned (1) =====\n\n");
        return 1;
    }

    // 2. get page directory index, page table index
    int pde_idx = (va & 0xFFC0) >> 11;
    int pte_idx = (va & 0x07C0) >> 6;

    unsigned short *pd_entry = pdbr + pde_idx;

    // 3-A. Page Directory Entry -> Page Table 이 Swap Out
    if (check_entry_swapped(*pd_entry)) {
        // Page Table이 Swap Out 되었다는 것은 가르키는 모든 Page가 swap out 상태이거나 invalid
        // printf("  Case A. Page Directory Entry (Page Table) is Swapped Out.\n");

        int pt_sfn = (*pd_entry & 0xfffc) >> 2;

        // Page Table이 Swap Out되어 있다는 것은 해당 PT이 가르키는 모든 Page가 Swap Out
        // Page Table이 가르키는 Page 중 하나라도 Present하면 Swap Out X)이기 때문
        // 또는 Page Table이 가르키는 모든 Page Frame이 invalid (0) 가능
        // PD Entry에서 `pt_swaps` 가져옴

        // 1) PD Entry → PT Entry → Page를 Swap In할 곳 pg_pfn or 만들 곳
        int new_pg_pfn = get_pfn_sequential(-1);

        // 2) PD Entry → PT를 Swap In할 곳 pt_pfn
        int new_pt_pfn = get_pfn_sequential(-1);

        if (new_pg_pfn < 0 || new_pt_pfn < 0) {
            // no free pfn
            return 1;
        }

        // printf("new_pg_pfn: %d, new_pt_pfn: %d\n", new_pg_pfn, new_pt_pfn);

        // 3) 설정
        // pg_free_block 생성 및 설정
        struct free_block *pg_free_block = malloc(sizeof(struct free_block));
        pg_free_block->pid = current->pid;
        pg_free_block->type = FB_TYPE_PAGE;
        pg_free_block->back_pfn = new_pt_pfn;

        // pt_free_block 생성 및 설정
        struct free_block *pt_free_block = malloc(sizeof(struct free_block));
        pt_free_block->pid = current->pid;
        pt_free_block->type = FB_TYPE_PAGE_TBL;
        pt_free_block->back_pfn = current->pd_pfn;

        // free_list에 넣음
        // *pg_pfn, pt_pfn을 둘 다 가져온 후 같이 pfn을 pf_list에 넣어야 swap out 안됨
        free_pf_list[new_pg_pfn] = pg_free_block;
        free_pf_list[new_pt_pfn] = pt_free_block;

        // 4) Page Table을 확인하기 위해 메모리에 올림
        unsigned short *ptbr = (unsigned short*)(pmem + (new_pt_pfn << 6));
        memcpy(ptbr, (swaps + (pt_sfn << 6)), (size_t)PAGE_SIZE);
        return_sfn(pt_sfn);

        // test log
        unsigned short *pt_entry1 = ptbr + 0;
        unsigned short *pt_entry3 = ptbr + 1;
        // printf("PT Entry1:\n");
        // print_entry(*pt_entry1);
        // printf("\n PT Entry3:\n");
        // print_entry(*pt_entry3);
        // printf("\n");

        // sf free block 제거
        free(free_sf_list[pt_sfn]);
        free_sf_list[pt_sfn] = NULL;

        // pt entry 가져옴
        unsigned short *pt_entry = ptbr + pte_idx;

        unsigned short new_pd_entry = 0;
        unsigned short new_pt_entry = 0;

        // A-① PT Entry가 swap out하다면
        if (check_entry_swapped(*pt_entry)) {
            // printf("A-① PT Entry가 swap out하다면\n");
            new_pd_entry = new_pt_pfn << 4 | 0x3; // dirty 1, present 1
            new_pt_entry = new_pg_pfn << 4 | 0x3; // dirty 1, present 1
        }

        // A-② PT Entry invalid
        else if (check_entry_invalid(*pt_entry)) {
            // printf("A-② PT Entry invalid\n");
            new_pd_entry = new_pt_pfn << 4 | 0x3; // dirty 1, present 1
            new_pt_entry = new_pg_pfn << 4 | 0x1; // dirty 0, present 1
        }

        else {
            // Cannot be reached
            // printf("  [OS] ERROR: PT Entry is ether not valid and present.\n");
            return 1;
        }

        // PD Entry -> PD 삽입
        *pd_entry = new_pd_entry;

        // A-① PT Entry가 swap out하다면
        if (check_entry_swapped(*pt_entry)) {
            int pg_sfn = (*pt_entry & 0xfffc) >> 2;

            // 페이지 swaps -> pmem 복사
            memcpy((pmem + (new_pg_pfn << 6)), (swaps + (pg_sfn << 6)), (size_t)PAGE_SIZE);
            return_sfn(pg_sfn);

            free(free_sf_list[pg_sfn]);
            free_sf_list[pg_sfn] = NULL;
            // printf("  Page SFN (%d) copyed to PMEM (%d)\n", pg_sfn, new_pg_pfn);
        }

        // A-② PT Entry invalid
        else if (check_entry_invalid(*pt_entry)) {
            // 페이지 초기화
            memset((pmem + (new_pg_pfn << 6)), 0, (size_t)PAGE_SIZE);
        }

        // PT Entry -> PT 삽입
        *pt_entry = new_pt_entry;

        // pf queue에 pfn 삽입
        enqueue(&pf_queue, new_pt_pfn);
        enqueue(&pf_queue, new_pg_pfn);
    }

    // 3-B. Page Directory Entry → Page Table이 Valid 한 경우
    else if (check_entry_valid(*pd_entry)) {
        // printf("  Case 3-B. Page Directory Entry -> Page Table is Valid.\n");

        // printf("  PD Entry:\n");
        // print_entry(*pd_entry);
        // printf("\n");

        int pt_pfn = (*pd_entry & 0xFFF0) >> 4;
        unsigned short *ptbr = (unsigned short*)(pmem + (pt_pfn << 6));
        unsigned short *pt_entry = ptbr + pte_idx;

        // printf("  --- OS: ptbr: %p, pte_idx: %d\n", ptbr, pte_idx);

        // 3-B-1) PT Entry -> Page 가 Swap Out된 경우
        if (check_entry_swapped(*pt_entry)) {
            // printf("    Case 3-B-1) PT Entry -> Page is Swapped Out.\n");
            // 페이지를 Swap in하고 PT Entry 수정

            // PT Entry에서 sfn을 가져옴
            int pg_sfn = (*pt_entry & 0xfffc) >> 2;

            // pg_pfn 받아옴 ← get_pfn_sequential(pt_pfn);
            // *pfn을 가져올 때 Page Table이 Swap Out 될 수 있음 (모든 entry swap out) → 방지 필요!!
            int new_pg_pfn = get_pfn_sequential(pt_pfn);

            if (new_pg_pfn < 0) {
                // no free pfn
                return 1;
            }

            // free_sf_list → free_pf_list로 free_block 이동
            // free_pf_list[new_pg_pfn] = free_sf_list[pg_sfn];
            // free_sf_list[pg_sfn] = NULL;
            struct free_block *new_pg_free_block = malloc(sizeof(struct free_block));
            new_pg_free_block->pid = current->pid;
            new_pg_free_block->type = FB_TYPE_PAGE;
            new_pg_free_block->back_pfn = pt_pfn;

            free_pf_list[new_pg_pfn] = new_pg_free_block;

            // PT Entry를 (pg_pfn << PFN_SHIFT | lsb)로 수정
            unsigned short new_pt_entry = new_pg_pfn << 4 | 0x3; // dirty 1, present 1
            *pt_entry = new_pt_entry;

            // Page를 SWAPS → PMEM으로 복사
            memcpy((pmem + (new_pg_pfn << 6)), (swaps + (pg_sfn << 6)), (size_t)PAGE_SIZE);

            // page sfn 반납
            return_sfn(pg_sfn);

            // pg_pfn을 pf_queue에 enqueue
            enqueue(&pf_queue, new_pg_pfn);
        }

        // 3-B-2) PT Entry가 Invalidate (Page가 Mapping X)
        else if (check_entry_invalid(*pt_entry)) {
            // printf("    Case 3-B-2) PT Entry -> Page is Invalid.\n");

            // page 새로 할당
            int new_pg_pfn = get_pfn_sequential(pt_pfn);
            unsigned short *pgbr = (unsigned short*)(pmem + (new_pg_pfn << 6));

            // printf("  new_pg_pfn: (%d)\n", new_pg_pfn);

            // PT Entry 생성
            // int lsb = 0b0001; // dirty 0, present 1
            unsigned short new_pt_entry_value = (new_pg_pfn << 4) | 0x1;

            // PT Entry 삽입
            *pt_entry = new_pt_entry_value;

            // printf("  PT Entry (%p):\n", pt_entry);
            // print_entry(*pt_entry);
            // printf("\n");

            // new_pg_pfn 페이지 초기화
            memset(pgbr, 0, (size_t)PAGE_SIZE);

            // new_pg_pfn을 pf_queue에 enqueue
            enqueue(&pf_queue, new_pg_pfn);

            // free block 새로 설정
            struct free_block *pg_free_block = malloc(sizeof(struct free_block));
            pg_free_block->pid = current->pid;
            pg_free_block->type = FB_TYPE_PAGE;
            pg_free_block->back_pfn = pt_pfn;

            // free_pf_list에 삽입
            free_pf_list[new_pg_pfn] = pg_free_block;
        }
    }

    // 3-C. Page Directory Entry 가 Invalidate (Page Table Mapping X)
    else if (check_entry_invalid(*pd_entry)) {
        // printf("  Case 3-C. Page Directory Entry -> Page Table is Invalid (not Mapped yet).\n");

        // Page Table 할당
        int new_pt_pfn = get_pfn_sequential(-1);
        if (new_pt_pfn < 0) {
            // no free pfn
            return 1;
        }

        unsigned short *ptbr = (unsigned short*)(pmem + (new_pt_pfn << 6));
        memset(ptbr, 0, (size_t)PAGE_SIZE);

        // Page 할당
        int new_pg_pfn = get_pfn_sequential(new_pt_pfn);
        if (new_pg_pfn < 0) {
            // no free pfn
            return 1;
        }

        unsigned short *pgbr = (unsigned short*)(pmem + (new_pt_pfn << 6));
        memset(pgbr, 0, (size_t)PAGE_SIZE);

        // printf("  new_pt_pfn: (%hu), new_pg_pfn: (%hu)\n", new_pt_pfn, new_pg_pfn);

        // Page Table Entry 생성
        // int pg_lsb = 0x1; // 0b01
        unsigned short pt_entry_value = new_pg_pfn << 4 | 0x1;
        unsigned short *pt_entry = ptbr + pte_idx;
        *pt_entry = pt_entry_value;

        // Page Directory Entry 생성
        // int pt_lsb = 0x3; // 0b11
        unsigned short pd_entry_value = new_pt_pfn << 4 | 0x3;
        *pd_entry = pd_entry_value;

        // printf("  PT Entry:\n");
        // print_entry(*pt_entry);
        // printf("\n  PD Entry:\n");
        // print_entry(*pd_entry);
        // printf("\n");

        // free block 생성
        struct free_block *pg_free_block = malloc(sizeof(struct free_block));
        pg_free_block->pid = current->pid;
        pg_free_block->type = FB_TYPE_PAGE;
        pg_free_block->back_pfn = new_pt_pfn;

        struct free_block *pt_free_block = malloc(sizeof(struct free_block));
        pt_free_block->pid = current->pid;
        pt_free_block->type = FB_TYPE_PAGE_TBL;
        pt_free_block->back_pfn = current->pd_pfn;

        free_pf_list[new_pg_pfn] = pg_free_block;
        free_pf_list[new_pt_pfn] = pt_free_block;

        // pt_pfn, pg_pfn pf_queue에 enqueue
        enqueue(&pf_queue, new_pt_pfn);
        enqueue(&pf_queue, new_pg_pfn);
    }

    // pmem_usage();
    // swap_usage();

    // printf("===== [OS] ku_pgfault_handler returned (0) =====\n\n");
    return 0;
}


// ============================================================
/** Terminate a Process and Reaps Page Frame and Swap Frames mapped */
int ku_proc_exit(unsigned short pid) {
    // printf("\n===== [OS]: Process Termination Function Called (pid: %hu) =====\n", pid);

    // PCB to terminate
    struct pcb *target = pcb_list[pid];

    if (target == NULL) {
        // printf("  [OS] ERROR: Cannot Find PCB which has PID (%hu)\n\n", pid);
        return 1;
    } else {
        // printf("  [OS] Process (pid: %hu) Found.\n", pid);
    }

    pcb_list[pid] = NULL;

    // free list에서 free block 보고 페이지 제거
    struct free_block *fb_target;
    for (int pf_idx = 0; pf_idx < pfnum; pf_idx++) {
        if (free_pf_list[pf_idx] != NULL && free_pf_list[pf_idx]->pid == pid) {
            fb_target = free_pf_list[pf_idx];
            memset(pmem + (pf_idx * PAGE_SIZE), 0, (size_t)PAGE_SIZE);
            free(fb_target);
            free_pf_list[pf_idx] = NULL;
        }
    }

    for (int sf_idx = 0; sf_idx < sfnum; sf_idx++) {
        if (free_sf_list[sf_idx] != NULL && free_sf_list[sf_idx]->pid == pid) {
            fb_target = free_sf_list[sf_idx];
            memset(swaps + (sf_idx * PAGE_SIZE), 0, (size_t)PAGE_SIZE);
            free(fb_target);
            free_sf_list[sf_idx] = NULL;
        }
    }

    // Set Current and pdbr to NULL
    current = NULL;
    pdbr = NULL;

    // free pcb
    free(target);

    // print_pcb_list();
    // pmem_usage();
    // swap_usage();

    // printf("===== [OS] Process (pid: %d) Termination Finished Successfully (0) =====\n\n", pid);
    return 0;
}