# Assignment #1 Kumoo

# **Multi-Level Page Table (OS MMU 구현)**

## **1. 자료형**

**정수형 자료**는 unsigned short로 통일함

`pfn` : `unsigned short pfn`

`sfn` : `unsigned short sfn`

`pid` : `unsigned short`

**과제에서 지정**

`pfnum`, `sfnum` : `int`

## 2. 자료구조

PCB List `struct pcb *pcb_list` (array)

Process Ready Queue `struct queue *ready_queue` (Queue)

PFN Queue (Page Replacement Policy) `struct queue *pf_queue` (Queue)

Free PFN List `struct free_block *free_pfn_list` (Array)

Free SFN List `struct free_block *free_sfn_list` (Array)

## 3. 구조체

**PCB**

```c
struct pcb {
		unsigned short pid;
		FILE *fd;
		unsigned short *pgdir;
		unsigned short pd_pfn;
		
		int vbase, vlength;
};
```

**Free Block**

```c
struct free_block {
		int type; // type 1 page directory, 2 page table, 3 page
		unsigned short pid; // pid
		int back_pfn; // inverse point
}
```

**Queue**

```c
struct queue {
    unsigned short *data;
    int front;
    int rear;
    int length;
    int max_length;
};
```

## 4. 알고리즘

### 4-1. `get_sfn_sequential()`

`free_sf_list`에서 for loop를 돌며 NULL인 `sfn`을 반환

for loop가 종료될 때까지 빈 `sfn`을 찾지 못한 경우 1 반환 

```c
for (int sfn = 0; sfn < sfnum; sfn++) {
		if (free_sf_list[sfn] == NULL) {
				return sfn;
		}
}
return -1; // error; no free page frame in swap space
```

### 4-2. `return_sfn(unsigned short sfn)`

해당 `sfn` Page Frame을 반환

1. `sfn` 페이지 0으로 초기화 (`memset`)
2. `free_sf_list`에서 free_block `free()`
3. `free_sf_list[sfn] = NULL`

### 4-3. `return_pfn(unsigned short pfn)`

Process가 종료될 때 호출됨 혹은 Swap 시 not dirty page 버릴 때

해당 `pfn` Page Frame을 반환

1. `pfn` 페이지 0으로 초기화 (`memset`)
2. `free_pf_list`에서 free_block `free()`
3. `free_pf_list[pfn] = NULL`

### 4-4. `get_pfn_sequential(int not_evict)`

***`get_pfn_sequential()` 한 후 반드시 `pfn`을 `pf_list`에 직접 enqueue 해주어야 함!!!**

1. for loop로 `free_pf_list` 순차 탐색
    
    → NULL인 `pfn` 반환
    
    ```c
    for (int pfn = 0; pfn < pfnum; pfn++) {
    		if (free_pf_list[pfn] == NULL) {
    				return pfn;
    		}
    }
    ```
    

1. 전부 차 있는 경우 evict할 page frame을 1개 찾음 → `pfn_to_evict`
    
    ```c
    while (1) {
    		pfn_to_evict = dequeue(&pf_queue); // pf_queue에서 FIFO로 pfn 가져옴
    		...
    }
    ```
    
    해당 `pfn_to_evict`가 swap out 될 수 있는지 검사
    
    **A. Page Table의 경우 모든 entry가 invalid or 모든 entry가 swapped-out 상태**
    
    - Page Table Entry가 모두 0
    - Page Table Entry가 모두 D 1 P 0 (swapped-out)
    
    → Page의 경우
    
    → `break;`
    
    **B. Page Table인데 하나라도 유효한 entry가 있는 경우 or `not_evict`와 같은 경우 무시**
    
    다시 `pf_queue`에 enqueue
    
    → `continue;`
    

1. evict할 Page Frame 종류에 따라
    
    Swap out 할 `sfn` 가져옴, 만약 남은 `sfn`이 없다면 -1 (오류) 반환
    
    ```c
    unsigned short sfn = get_sfn_sequential();
    
    if (sfn == -1) {
    		return -1;
    }
    ```
    
    **if A. 이 Page Frame이 Page Table 이라면**
   
    <img width="500px" alt="Untitled" src="https://github.com/leehe228/OS_kumoo/assets/37548919/7236fe49-1735-4be4-9006-2d504facf764">
 
    ```c
    if (free_pf_list[pfn_to_evict]->type == 2) {
    		...
    }
    ```
    
    *이 Page Table은 Swap Out 할 수 있는 Page Table임 (2-a에서 검증)
    
    **if A-1) 이 Page Table의 모든 Entry가 invalid 하다면 빈 페이지 테이블 → 버림**
    
    Page Directory에서 `pfn_to_evict` 가르키는 PD Entry를 invalidate (0)로 수정
    
    해당 Page를 0으로 초기화 (`memset`)
    
    Swap Out할 Page Table의 free_block을 `free()`
    
    **if A-2) 이 Page Table이 가르키는 Page들의 `free_block`을 수정**
    
    `free_sf_list` 순차 검색해서 back pointer가 이 `pfn_to_evict`인 페이지들 찾음
    
    ```c
    for (int i = 0; i < pfn; i++) {
    		if (free_sf_list[pfn] != NULL 
    		    && free_sf_list[pfn]->back_pf == pfn_to_evict) {
    				...
    		}
    }
    ```
    
    (해당 Page Table이 Swap Out 되는 것은 모든 entry가 Swap Out이기 때문에 `free_pf_list` 검사 할 필요 없음)
    
    즉, 이 page frame이 가르키고 있는 페이지들을 찾음
    
    페이지들 free_block의 `back_pf`를 `-sfn`으로 수정 (`sfn`은 음수!!)
    
    Page Directory 수정
    
    Page Directory에서 `pfn_to_evict` 가르키는 PD Entry 수정 (`SFN`) 
    
    dirty 1 present 0
    
    해당 Page를 PMEM → SWAPS 복사
    
    해당 Page를 0으로 초기화
    
    ```c
    memcpy(pfn_to_evict_addr, sfn_addr, (size_t)PAGE_SIZE);
    memset(pfn_to_evict_addr, 0, (size_t)PAGE_SIZE);
    ```
    
    Swap Out할 Page Table의 `free_block`을 `free_pf_list` → `free_sf_list`로 이동
    
    ⇒ `pfn_to_evict` 반환
    
    **if B. 이 Page Table이 일반 Page라면**
    
    <img width="500px" alt="Untitled 1" src="https://github.com/leehe228/OS_kumoo/assets/37548919/e6b96225-3947-4560-8d6a-a278ee72ab49">

    ```c
    else if (free_pf_list[pfn_to_evict]->type == 3) {
    		...
    }
    ```
    
    Page Table을 수정
    
    **if B-1) 해당 Page를 가르키는 PT Entry가 not dirty라면 → 버림**
    
    해당 Page를 가르키는 PT Entry를 invalidate (0)으로 수정
    
    해당 페이지를 0으로 초기화 (`memset`)
    
    Swap Out할 Page의 `free_block`을 `free()`
    
    → `return_pfn()`
    
    **if B-2) 해당 Page를 가르키는 PT Entry가 dirty라면 → Swap Out**
    
    Page Table 수정
    
    해당 페이지를 가르키는 PT Entry를 수정 (`SFN`) + dirty 1 present 0
    
    해당 Page를 PMEM → SWAPS로 복사 (`memcpy`)
    
    해당 페이지를 0으로 초기화 (`memset`)
    
    Swap Out할 Page Table의 `free_block`을 `free_pf_list` → `free_sf_list`로 이동
    
    ⇒ `pfn_to_evict` 반환
    

### 4-5. `ku_pgfault_handler`

1. Virtual Address가 Address Space 범위 내인지 Segmentation Fault 검사 → 1 반환
    
    ```c
    if (vbase >= va || va > vbase + vlength) {
    		// Segmentation Fault 
    		return 1;
    }
    ```
    

1. `va`에서 `pd_idx`, `pt_idx` 가져옴
    
    ```c
    int pd_idx = (va & PD_MASK) >> PD_SHIFT;
    int pt_idx = (va & PT_MASK) >> PT_SHIFT;
    ```
    

1. 각 케이스별 처리
    
    <img width="500px" alt="Untitled 2" src="https://github.com/leehe228/OS_kumoo/assets/37548919/67ba54af-faca-49f4-8649-d84d0a436383">

    <img width="500px" alt="Untitled 3" src="https://github.com/leehe228/OS_kumoo/assets/37548919/2a9e107e-6060-4aaa-a83a-7d39a779c2d7">

    **if A. Page Directory Entry → Page Table이 Swap Out된 경우**
    
    Page Table이 Swap Out되어 있다는 것은 해당 PT이 가르키는 모든 Page가 Swap Out
    
    ~~(Page Table이 가르키는 모든 Page가 invalidate하면 Swap Out X~~ 
    
    ~~→ `get_pfn_sequential()` 함수에서 보장 필요!~~
    
    Page Table이 가르키는 Page 중 하나라도 Present하면 Swap Out X)이기 때문
    
    **또는 Page Table이 가르키는 모든 Page Frame이 invalid (0) 가능**
    
    PD Entry에서 `pt_swaps` 가져옴
    
    **1) PD Entry → PT Entry → Page를 Swap In할 곳 `pg_pfn` or 만들 곳**
    
    `pg_pfn` 받아옴 ← `get_pfn_sequential()`
    
    **2) PD Entry → PT를 Swap In할 곳 `pt_pfn`**
    
    `pt_pfn` 받아옴 ← `get_pfn_sequential()`
    
    **3) 설정**
    
    pg_free_block 생성 및 설정 (`type = 3`, `back_pfn = pt_pfn`)
    
    pt_free_block 생성 및 설정 (`type = 2`, `back_pfn = current→pd_pfn`)
    
    free_list에 넣음
    
    *`pg_pfn`, `pt_pfn`을 둘 다 가져온 후 같이 `pfn`을 pf_list에 넣어야 swap out 안됨
    
    **4) Page Table 확인 위해 메모리로 올림**
    
    PT Page를 SWAPS → PMEM으로 복사 
    
    PT `sfn` SWAPS 0 초기화
    
    **A-① PT Entry가 swap out하다면**
    
    PD Entry 설정 (`pt_pfn << PFN_SHIFT | lsb`) 
    
    PT Entry 설정 (`pg_pfn << PFN_SHIFT | lsb`)
    
    *`lsb`는 dirty 1, present 1 `0b0011` (swap in 이므로 **dirty가 1임!!**)
    
    **A-② PT Entry invalid**
    
    PD Entry 설정 (`pt_pfn << PFN_SHIFT | lsb`) dirty 1 present 1
    
    PT Entry 설정 (`pg_pfn << PFN_SHIFT | lsb`) **dirty 0** present 1
    
    → PT의 경우 Page 새로 할당이므로 dirty bit 0!!!
    
    PD Entry→PD에 삽입
    
    **A-① 만약 PT Entry가 swap out 하다면** 
    
    복사 Page SWAPS → PMEM
    
    Swaps에 Page `sfn` 초기화 (0)
    
    **A-② 만약 PT Entry가 invalid 하다면** 
    
    pass
    
    PT Entry → PT 삽입
    
    `pf_queue`에 `pg_pfn`, `pt_pfn` enqueue
    
    **if B. Page Directory Entry → Page Table이 Valid 한 경우**
    
    **if B-1) PT Entry → Page가 Swap Out된 경우**
    
    <img width="500px" alt="Untitled 4" src="https://github.com/leehe228/OS_kumoo/assets/37548919/ac87a6b0-cdf0-41a6-9154-1678fda2c877">
    
    Page를 Swap In하고 PT Entry를 수정
    
    `pg_pfn` 받아옴 ← `get_pfn_sequential(pt_pfn);`
    
    *`pfn`을 가져올 때 Page Table이 Swap Out 될 수 있음 (모든 entry swap out) → **방지 필요!!**
    
    PT Entry에서 `sfn`을 가져옴
    
    `free_sf_list` → `free_pf_list`로 `free_block` 이동
    
    PT Entry를 (`pg_pfn << PFN_SHIFT | lsb`)로 수정
    
    *`lsb`는 dirty 1, present 1 `0b0011` (Swap in이므로 **dirty가 1임!!**)
    
    PT Entry를 PT에 삽입
    
    Page를 SWAPS → PMEM으로 복사
    
    SWAPS의 `sfn` 페이지를 0으로 초기화
    
    `return_sfn(sfn)` (`sfn`을 free 상태로 변환)
    
    `pg_pfn`을 `pf_queue`에 enqueue
    
    **if B-2) PT Entry가 Invalidate (Page가 Mapping X)**
    
    <img width="500px" alt="Untitled 5" src="https://github.com/leehe228/OS_kumoo/assets/37548919/57e28e54-b6db-461d-b65e-d4c02ae7708a">
    
    Page 새로 할당 후 0으로 초기화, PT Entry를 수정
    
    `pg_pfn` 받아옴 ← `get_pfn_sequential(pt_pfn)`
    
    *`pfn`을 가져올 때 Page Table이 Swap Out 될 수 있음 (모든 entry invalid) → **방지 필요!!**
    
    PT Entry 생성 (`pg_pfn << PFN_SHIFT | lsb`)
    
    *`lsb`는 dirty 0, present 1 `0b0001` (새로 생성 이므로 **dirty가 0임!!**)
    
    PT Entry를 PT에 삽입
    
    `pg_pfn` 페이지를 0으로 초기화
    
    `pg_pfn`을 `pf_queue`에 enqueue
    
    free_block 새로 생성 및 설정 (`pid`, `type=3`, `back_pfn=pt_pfn`)
    
    `free_pf_list`에 free_block 삽입
    
    **if C. Page Directory Entry가 Invalidate (Page Table Mapping X)**
    
   <img width="500px" alt="Untitled 6" src="https://github.com/leehe228/OS_kumoo/assets/37548919/e0bc4881-250e-4d8f-97ca-101595041df0">

    
    First Touch, PT, Page 모두 할당 필요
    
    **Page Table 할당**
    
    `pt_pfn` 가져옴 ← `get_pfn_sequential()`
    
    Page Table 초기화 (0으로 `memset`)
    
    ```c
    unsigned short *pt_addr = get_pfn_addr(pt_pfn);
    memset(pt_addr, 0, (size_t)PAGE_SIZE);
    ```
    
    **Page 할당**
    
    `pg_pfn` 가져옴 ← `get_pfn_sequential()`
    
    Page 초기화 (0으로 `memset`)
    
    ```c
    unsigned short *pg_addr = get_pfn_addr(pg_pfn);
    memset(pg_addr, 0, (size_t)PAGE_SIZE);
    ```
    
    PT Entry 생성 → Page Table 삽입 (`pg_pfn << PFN_SHIFT | lsb`)
    
    *lsb는 dirty bit 0, present 1 (`0b0001`)
    
    PD Entry 생성 → Page Directory 삽입 (`pt_pfn << PFN_SHIFT | lsb`)
    
    *lsb는 dirty bit 1, present 1 (`0b0011`) Page Table이므로 **Dirty Bit 1!!**
    
    free_block 생성 및 설정 (pid, type PT는 2, Page는 3)
    
    `pg_free_block→back_pfn = pt_pfn`
    
    `pt_free_block_back->ack_pfn = current->pgdir`
    
    free_pf_list에 삽입
    
    `pt_pfn`, `pg_pfn` pf_queue에 enqueue
    

### 4-6. `ku_freelist_init`

1. `args[1]`에서 파일명을 가져오고 파일을 `fopen`
2. `pcb_list`, `ready_queue`, `pf_queue` 초기화
    
    ```c
    // Initialize PCB List (Double Pointer Array)
    pcb_list = (struct pcb**)malloc(sizeof(struct pcb*) * PCB_LIST_LENGTH);
    
    // Initialize a Process Ready Queue
    queue_init(&ready_queue, READY_QUEUE_LENGTH);
    
    // Initialize a PFN Queue (for page frame replacement policy)
    queue_init(&pf_queue, PF_QUEUE_LENGTH);
    ```
    
3. 각 프로세스에 대해 
    1. PCB 인스턴스 생성 `new_pcb`
    2. `new_pcb`의 pid 설정, `pid`를 `ready_queue`에 enqueue
    3. 파일을 읽음
    
    1. `new_pcb`의 `vbase`, `vlength` 설정, fd 설정
    2. 빈 `pfn` 하나 가져옴 → `new_pcb`의 `pgdir` 설정, `pd_pfn` 설정
    3. Free Block 인스턴스 생성 `new_free_block`
    4. `new_free_block`의 type 1, pid 설정
    5. `free_pf_list[pid] = new_free_block` free block 리스트에 넣음
    6. `pcb_list[pid] = new_pcb` pcb 리스트에 넣음
4. 파일 `fclose`

### 4-7. `ku_scheduler`

1. current가 `NULL`(실행중 프로세스 없음)이고 Ready Queue가 비어있다면 → 프로세스 없음 1 반환
2. current가 `NULL`이 아니고 (실행중 프로세스 있음) Ready Queue가 비어있다면
    
    → 현재 실행중인 프로세스 계속 실행 0 반환
    
3. ready queue에서 `next_pid`를 dequeue해서 가져옴
4. `current`를 `pcb_list[next_pid]`로 설정
    
    만약 `current`가 `NULL`이라면 오류 1 반환
    
5. `pdbr`을 `current→pgdir`로 설정
6. 만약 `pid`가 10이 아니라면 ready queue에 `pid`를 enqueue

### 4-8. `ku_proc_exit`

1. 해당 pid를 가진 process가 존재하는지 검사 → 없다면 1 반환
2. 해당 Process의 PCB를 가져옴
    
    ```c
    struct pcb *target = pcb_list[pid];
    ```
    
3. `free_pf_list`에서 free_block 보고 페이지를 전부 제거
    
    ```c
    for (int pf_idx = 0; pf_idx < pfnum; pf_idx++) {
            if (free_pf_list[pf_idx] != NULL 
    		        && free_pf_list[pf_idx]->pid == pid) {
                fb_target = free_pf_list[pf_idx];
                memset(pmem + (pf_idx * PAGE_SIZE), 0, (size_t)PAGE_SIZE);
                free(fb_target);
                free_pf_list[pf_idx] = NULL;
            }
        }
    ```
    
4. `free_sf_list`에서 free_block 보고 페이지를 전부 제거
    
    ```c
    for (int sf_idx = 0; sf_idx < sfnum; sf_idx++) {
            if (free_sf_list[sf_idx] != NULL 
    		        && free_sf_list[sf_idx]->pid == pid) {
                fb_target = free_sf_list[sf_idx];
                memset(swaps + (sf_idx * PAGE_SIZE), 0, (size_t)PAGE_SIZE);
                free(fb_target);
                free_sf_list[sf_idx] = NULL;
            }
        }
    ```
    
5. `current`, `pdbr`을 `NULL`로 (다음 scheduler 호출 시 설정)
6. `pcb_list`에서 PCB를 `free()`, `pcb_list[pid] = NULL`
