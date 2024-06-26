# Assignment #1 Kumoo
**Multi-Level Page Table (OS MMU 구현)**

## How to run?
```bash
gcc ./kumoo.c -o kumoo
```

```bash
./kumoo input.txt
```
본 코드는 Ubuntu 22.04 Server (x86-64) 에서 테스트하였습니다.
<br>

---

<br>

# 설계 자료 (Design Specification)

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

<br>

---

<br>

# 보고서 Report

## 1. 변수, 상수 및 자료구조 Design

### 1-1. 기호 상수

`#define` 매크로로 작성한 기호 상수입니다. 

| 상수 | 값 | 설명 |
| --- | --- | --- |
| ADDR_SIZE | 16 | 본 시스템에서 사용하는 Address Space는 16-bit Addressing을 사용합니다. |
| PAGE_SIZE | 64 | 16-bit Addressing에서 offset은 6-bit이므로 한 페이지의 크기는 2^6, 즉 64B입니다. |
| PCB_LIST_LENGTH | 16 | 본 시스템에서 프로세스는 최대 10개를 포함할 수 있느나 여유를 두어 PCB List의 길이를 16으로 설정하였습니다. |
| PF_QUEUE_LENGTH | 4096 | PF Queue는 Page Replacement Policy에서 FIFO 방식으로 evict(swap-out)할 PFN을 선정합니다. PFN은 12-bit이므로 최대 길이는 2^12, 즉 4096으로 설정하였습니다. |
| READY_QUEUE_LENGTH | 16 | Ready Queue는 실행을 기다리는 Ready State인 프로세스의 PID를 저장합니다. 본 시스템에서 프로세스는 최대 10개를 포함할 수 있으나 여유를 두어 16으로 설정하였습니다. |

### 1-2. 주요 자료형

| 변수 | 자료형 | 설명 |
| --- | --- | --- |
| pfn | int | 물리 메모리의 Page Frame Number |
| sfn | int | Swap 공간의 Swap Frame Number |
| pid | unsigned short | Process ID |
| entry | unsigned short* | Page Entry |

Page Entry의 경우 16-bit이므로 크기가 2B입니다. 따라서 2B의 크기를 가지는 unsigned short로 연산이 가능합니다.

### 1-3. 자료구조

**PCB List**

```c
struct pcb **pcb_list;
```

PCB List는 PCB 구조체를 저장하기 위한 리스트입니다. 배열(array)을 사용하였으며 동적 할당하여 Process별 PCB 구조체 인스턴스를 생성하여 PCB List 배열에 삽입합니다. 사용되지 않는 PID의 경우 NULL값이 들어있습니다. `ku_proc_init()` 함수에서 동적할당하여 초기화합니다.

**Process Ready Queue**

```c
struct queue *ready_queue;
```

Context Switch 시 Scheduler에서 Round Robin (FIFO) 방식을 따르므로 큐를 사용합니다.

**PFN Queue**

```c
struct queue *pf_queue;
```

Swap-out할 페이지를 고를 때 (Page Replacement Policy) FIFO 방식을 따르므로 큐를 사용합니다.

**Free PF List와 Free Sf List**

```c
struct free_block **free_pf_list; 
struct free_block **free_sf_list;
```

Free List를 물리메모리와 Swap 공간 각각 Free Block 배열로 관리합니다.

### 1-4. 구조체

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

과제에서 주어진 코드에 아래 변수를 추가했습니다.

`pd_pfn`: Page Directory가 위치한 PFN입니다. Free List 순차검색으로 찾을 수 있지만, 코드를 단순화하기 위하여 PCB 구조체 내에 변수로 할당하였습니다.

`vbase`, `vlength`: 각 프로세스 txt 파일 Data Segment(”d”)에 적혀있는 숫자입니다. 이 프로세스에게 할당된 Virtual Address Space의 base 주소와 length를 나타냅니다.

**Free Block**

```c
struct free_block {
		int type; 
		unsigned short pid;
		int back_pfn;
}
```

Free List는 비어있는 페이지 프레임을 쉽게 찾기 위한 자료구조로, 단순히 해당 Page Frame이 사용중인지 여부를 포함하여, 아래와 같은 부가 정보를 포함하도록 하였습니다.

`type`: 해당 Page Frame의 종류입니다. Page Directory일 경우 1, Page Table일 경우 2, 실제 쓰기/읽기 작업이 발생하는 Page Frame일 경우 3 값을 가집니다.

`pid`: 해당 Page Frame을 사용하는 Process의 PID를 저장합니다.

`back_pfn`: 실제 운영체제에서 inverse point table과 비슷한 역할을 합니다. 해당 페이지를 참조하는 Entry가 포함된 페이지 PFN을 저장합니다. 

예를 들어, 해당 페이지가 Page Table이라면, 해당 Page Table을 가르키는 Page Directory Entry가 포함된 Page Directory의 PFN이 저장될 것입니다.

또한, 해당 페이지를 참고하는 상위 페이지가 Swap-Out 되어있을 수 있습니다. 이때는 `back_pfn`에 SFN을 저장합니다. 이때, PFN과 SFN을 구분할 수 없으므로 SFN은 음수로 저장합니다. OS는 `back_pfn`에 저장된 값이 음수라면 SFN으로 취급합니다. SFN은 인덱스가 1부터 시작하므로, -1 이하의 값은 SFN, 0 이상의 값은 PFN을 나타냅니다.

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

FIFO 선입선출 방식으로 데이터를 관리하는 큐를 구현하기 위한 구조체입니다. Queue는 Array를 사용한 Inode Circular Queue로 구현하였으며, 고정된 길이의 배열에서 front가 top의 인덱스를, rear가 bottom의 인덱스를 저장하며, 최대 길이를 넘지 않는 한, front와 rear가 배열의 끝에 다다를 시 맨 처음으로 돌아가는 Circular Queue의 구조를 채택하였습니다.

Queue를 사용하기 위해 아래 함수를 구현하여 사용하였습니다.

`void queue_init(struct queue **_queue, int max_length)`: queue를 max_length 길이를 갖도록 데이터 배열을 동적할당하여 초기화합니다.

`int queue_check_empty(const struct queue *_queue)`: queue가 비어있는지 여부를 반환합니다. 비어있는 경우 dequeue 작업 시 오류가 발생합니다.

`int queue_check_full(const struct queue *_queue)`: queue가 가득 차있는지 여부를 반환합니다. 가득 차 있는 경우 enqueue 작업 시 오류가 발생합니다.

`int queue_length(const struct queue *_queue)`: 현재 queue의 길이를 반환합니다.

`void enqueue(struct queue **_queue, unsigned short item)`: 인자로 받은 원소를 queue에 bottom에 삽입합니다. (Enqueue)

`unsigned short dequeue(struct queue **_queue)`: queue에서 top에 위치한 원소를 제거하고 반환합니다. (Dequeue)

## 2. 알고리즘 설명

### 2-1. `ku_freelist_init()`

물리 메모리와 Swap 공간에 비어있는 페이지를 관리하기 위한 자료구조인 `free_pf_list`와 `free_sf_list` 배열을 동적할당하고 초기화합니다.

`free_pf_list`와 `free_sf_list` 배열의 길이는 각각 전역변수 pfnum과 sfnum에 의해 설정됩니다.

이외의 작업은 하지 않습니다.

### 2-2. `ku_proc_init()`

1. `argv` 배열에서 프로세스 실행 정보가 적혀있는 input 파일명을 가져옵니다.
2. PCB List와 PF Queue, Ready Queue를 동적 할당하고 초기화합니다.
3. 파일을 열고, 프로세스 정보를 읽습니다. 각 프로세스별로 아래 단계를 따라 처리합니다.
    1. 각 프로세스별 새로운 PCB 구조체 인스턴스를 동적 할당합니다.
    2. 프로세스별 파일을 `fopen`으로 읽고 file descriptor를 PCB 내의 `fd` 변수에 저장합니다.
    3. PCB에 PID와 파일을 읽어 `vbase`, `vlength`를 저장합니다.
    4. Page Directory를 할당하기 위해 `get_pfn_sequential()` 함수로부터 비어있는 PFN 번호를 받아옵니다. 해당 페이지를 Page Directory로 사용합니다.
    5. 페이지를 할당받았으므로 Free Block 구조체 인스턴스를 동적 할당합니다.
    6. Free Block 인스턴스의 Type을 Page Table(=`1`), PID를 설정합니다. Page Directory는 Inverse Pointer를 가지지 않으므로 `back_pfn`은 설정하지 않습니다.
    7. Page Directory의 PFN과 주소를 PCB의 `pgdir`과 `pd_pfn`에 각각 저장합니다.
    8. PCB List 배열에 PID번째 인덱스에 PCB 인스턴스를 할당합니다.
    9. Free PF List 배열에 Page Directory의 PFN번째 인덱스에 Free Block을 할당합니다.
4. 모든 프로세스에 대해 PCB와 Free Block, Page Directory 할당 작업이 종료되면 열었던 파일을 닫습니다.
5. 작업을 성공했으므로 0을 반환합니다.

### 2-3. `ku_scheduler()`

1. 현재 실행중인 PCB를 참조하는 `current` 변수가 NULL이고, Ready Queue가 비어있다면, 실행할 프로세스가 없는 것이므로 1을 반환합니다.
2. 현재 실행중인 프로세스는 존재(`current` 변수가 NULL이 아님)하지만, Ready Queue가 비어있다면, 현재 실행중인 프로세스가 1개 남은 것이므로 Context Switch 하지 않고 실행하던 프로세스를 계속 실행합니다.
3. 위 두 케이스가 아니라면, Context Switch가 가능하므로 Ready Queue에서 다음번에 실행할 프로세스의 PID(`next_pid`)를 Enqueue하여 가져옵니다. 만약 `next_pid`의 PCB가 존재하지 않는다면 이미 종료된 프로세스이므로 1을 반환합니다.
4. Context Switch를 진행합니다. 다음번에 실행할 프로세스의 PCB를 참조하도록 `current` 변수와 `pdbr` 변수 값을 수정합니다.
5. 만약 현재 실행중이었던 즉, 매개변수로 넘어온 PID 인자의 값이 10 미만이라면 Ready State로 전환되었으므로 Ready Queue에 Dequeue합니다. (PID 인자 값이 10인 것은 CPU가 프로세스 최초 실행 시 호출한 값이므로 Ready Queue에 삽입하지 않습니다)
6. 작업을 성공했으므로 0을 반환합니다.

### 2-4. `get_pfn_sequential()`

1. 물리 메모리 페이지에서 빈 공간이 있는지 순차 탐색(sequential search) 하기 위해 for loop를 돌며 Free PF List 중 NULL을 가진 PFN을 반환, 이때 인자로 넘어온 `not_evict_pfn`과 같은 경우 반환하지 않고 검색을 계속합니다.
2. 만약 for loop로 비어있는 페이지를 찾지 못한 경우 모든 Page가 사용중이므로 Swap을 해야 합니다.
3. PF Queue의 top부터 bottom까지 순서대로 evict할 수 있는 페이지가 있는지 검사합니다.
    1. 먼저 PF Queue에서 top의 PFN을 Dequeue합니다 (`pfn_to_evict`)
    2. 해당 페이지가 evict될 수 있는지 검사합니다.
        - 해당 페이지가 Page Directory인 경우 evict될 수 없습니다 (Page Directory의 PFN은 PF Queue에 들어가지 않음)
        - 해당 페이지가 일반 Page Frame인 경우 evict될 수 있습니다.
        - 해당 페이지가 Page Table인 경우 모든 Entry가 Invalid하거나, 참조하는 페이지가 Swap-out된 경우 evict 될 수 있으며, 하나라도 present한 Page를 Entry가 참조하는 경우 evict 될 수 없습니다.
    3. 위 조건을 만족하는 PFN을 찾은 경우 for문을 종료, 만족하지 않는 경우 해당 PFN을 PF Queue에 다시 Enqueue하고 for loop 계속 진행 (`continue`)
4. Evict할 페이지가 일반 페이지인 경우 해당 페이지의 `back_pfn`으로 해당 페이지를 참조하는 Entry를 통해 해당 페이지가 dirty한지 검사합니다. 만약 dirty한 경우 해당 페이지를 Swap-out하고 Entry를 수정합니다. 만약 dirty하지 않은 경우 폐기하고 Entry를 0으로 수정합니다.
5. Evict할 페이지가 위 조건을 만족하는 Page Table일 경우
    1. Page Table의 모든 Entry가 Invalid한 경우 해당 페이지를 폐기합니다. `back_pfn`을 통해 이 Page Table을 참조하는 Page Directory Entry를 찾아 0으로 수정합니다.
    2. Page Table의 유효한 Entry가 모두 Swap-out된 경우 Free SF List를 순차검색하여 Free Block의 `back_pfn`을 해당 Page Frame이 Swap-out될 SFN으로 수정하여 inverse pointer를 수정합니다. 또한, 해당 Page Table의 `back_pfn`을 통해 이 Page Table을 참조하는 Page Directory Entry를 찾아 수정합니다.
6. Evict할 페이지가 일반 Page Frame이라면
    1. 해당 Page Frame의 `back_pfn`을 통해 해당 Page를 참조하는 Page Table Entry를 찾습니다.
    2. 만약 Page Table Entry가 dirty하지 않다면 해당 페이지를 폐기하고 Page Table Entry를 0으로 수정합니다.
    3. 만약 Page Table Entry가 dirty하다면 해당 페이지를 Swap-out합니다. 물리 메모리의 해당 페이지를 Swap 공간으로 복사합니다. 이에 따라 Page Table Entry를 수정하고, 해당 페이지의 Free Block을 Free PF List에서 Free SF List로 옮깁니다. 
7. 위 (Swap-out 또는 폐기) 작업을 통해 비어있도록 설정한 페이지의 `pfn_to_evict`를 반환합니다.

### 2-5. `ku_pgfault_handler()`

1. 변환하고자 하는 Virtual Address `va`가 Virtual Address Space 범위 내인지 검사합니다.
    
    `va`는 해당 프로세스 PCB의 `vbase`보다 크거나 같고, `vbase + vlength`보다 작아야 합니다. 범위를 벗어난 경우 Segmentation Fault이므로 1을 반환합니다.
    
2. `va`에서 Page Directory Index (`pd_idx`)와 Page Table Index (`pt_idx`)를 가져옵니다.
    
    ```c
    int pd_idx = (va & PD_MASK) >> PD_SHIFT;
    int pt_idx = (va & PT_MASK) >> PT_SHIFT;
    ```
    
3. 각 케이스별로 처리합니다. 
    
    **Case A. Page Directory Entry → Page Table이 Swap-out된 경우**
    
    Page Table이 Swap-out 되어있다는 것은 유효한 Entry가 모두 Swap-out 되어있다는 의미입니다.
    
    Page Table을 Swap-out할 경우 모든 Entry가 Invalid한 경우 폐기하므로 위 경우를 보장합니다.
    
    1. Page를 Swap-in할 PFN(`pg_pfn`)을 가져옵니다.
    2. Page Table을 Swap-in할 PFN(`pt_pfn`)을 가져옵니다.
    3. Page와 Page Table을 위한 Free Block을 동적 할당하고 설정합니다. (PID와 Type)
        
        `back_pfn`의 경우 Page는 `pt_pfn`, Page Table의 경우 `pd_pfn`으로 설정합니다.
        
    4. 두 Free Block을 Free PF List에 삽입합니다.
    5. Page Table을 확인하기 위해 메모리로 복사합니다.
        
        `pd_idx`에서 가져온 `pt_sfn`번째 Swap 공간의 페이지는 0으로 초기화합니다.
        
    6. 해당 Page를 참조하는 Page Table Entry를 확인합니다.
        
        1) Page Table Entry가 Swap-out 되어있다면
        
        PD Entry를 설정합니다 (`pt_pfn` 포함, dirty 1, present 1)
        
        PT Entry를 설정합니다 (`pg_pfn` 포함, dirty 1, present 1)
        
        2) Page Table Entry가 Invalid하다면
        
        PD Entry를 설정합니다 (`pt_pfn` 포함, dirty 1, present 1)
        
        PT Entry를 설정합니다 (`pg_pfn` 포함, dirty 0, present 1)
        
    7. Page Directory Entry를 Page Directory `pd_idx`번째 Entry에 삽입합니다.
    8. 해당 Page를 참조하는 Page Table Entry를 확인합니다.
        
        1) Page Table Entry가 Swap-out 되어있다면
        
        Swap 공간에서 물리 메모리로 페이지 정보를 복사합니다.
        
        기존에 사용중이던 Swap 공간의 페이지는 반환합니다.
        
        2) Page Table Entry가 Invalid하다면
        
        할당받은 새 페이지를 0으로 초기화합니다.
        
    9. Page Table Entry를 Page Table `pt_idx`번째 Entry에 삽입합니다.
    10. `pg_pfn`과 `pt_pfn`을 PF Queue에 Enqueue합니다.
    
    **Case B. Page Directory Entry → Page Table이 Valid한 경우**
    
    **Case B-1) Page Table Entry → Page가 Swap-out된 경우**
    
    1. Page를 Swap-in 하기 위한 PFN(`pg_pfn`)을 가져옵니다.
        
        이때, 이 Page를 참조하는 Page Table이 Swap-out되는 것을 방지하기 위해 `get_pfn_sequential()` 함수 호출 시 인자로 `pt_pfn`을 넘겨줍니다.
        
    2. `pt_idx`를 참조하여 Page Table Entry에서 SFN을 가져옵니다.
    3. Free SF List SFN번째 Free Block을 Free PF List `pg_pfn`번째 인덱스로 이동합니다.
    4. Page Table Entry를 생성합니다. (`pg_pfn` 포함, Dirty 1, Present 1)
    5. Page Table Entry를 Page Table에 삽입합니다.
    6. Page 데이터를 Swap 공간에서 물리 메모리로 복사합니다.
    7. Swap 공간에서 SFN번째 페이지를 0으로 초기화합니다.
    8. `pg_pfn`을 PF Queue에 Enqueue합니다.
    
    **Case B-2) Page Table Entry → Page가 Invalid (Mapping되지 않은) 경우**
    
    1. Page를 새로 할당하기 위한 PFN(`pg_pfn`)을 가져와 0으로 초기화합니다.
        
        이때, 이 Page를 참조하는 Page Table이 Swap-out되는 것을 방지하기 위해 `get_pfn_sequential()` 함수 호출 시 인자로 `pt_pfn`을 넘겨줍니다.
        
    2. Page Table Entry를 생성합니다. (`pg_pfn`을 포함, Dirty 0, Present 1)
    3. Page Table Entry를 Page Table에 삽입합니다.
    4. Page Frame을 위한 Free Block을 동적 할당하고 설정합니다. (PID와 Type)
        
        `back_pfn`의 경우 해당 페이지를 참조하는 Page Table의 `pt_pfn`으로 설정
        
    5. Free Block을 Free PF List에 삽입합니다.
    6. `pg_pfn`을 PF Queue에 Enqueue합니다.
    
    **Case C. Page Directory Entry → Page Table이 Invalid (Mapping되지 않은) 경우**
    
    1. First Touch이므로 Page Table, Page Frame 모두 할당이 필요합니다.
    2. Page Table을 할당하기 위한 PFN(`pt_pfn`)을 가져와 0으로 초기화합니다.
    3. Page Frame을 할당하기 위한 PFN(`pg_pfn`)을 가져와 0으로 초기화합니다.
    4. Page Table Entry를 생성하여 Page Table에 삽입합니다. (Dirty 0, Present 1)
    5. Page Directory Entry를 생성하여 Page Directory에 삽입합니다. (Dirty 1, Present 1)
        
        *페이지 테이블은 Entry 수정 작업이 있었으므로 Dirty Bit을 1로 설정합니다.
        
    6. 각 Page Frame에 대한 Free Block을 동적 할당하고 설정합니다. (PID와 Type)
        
        `back_pfn`의 경우 Page는 `pt_pfn`, Page Table의 경우 `pd_pfn`으로 설정합니다.
        
    7. Free Block을 Free PF List에 삽입합니다.
    8. `pt_pfn`과 `pd_pfn`을 PF Queue에 Enqueue합니다.

### 2-6. `ku_proc_exit()`

1. 종료할 프로세스의 PCB를 찾아 참조합니다. 만약 인자로 넘어온 PID를 갖는 프로세스의 PCB가 존재하지 않는다면 이미 종료되었거나 오류이므로 1을 반환합니다.
2. Free PF List를 순차 탐색하여 물리 메모리의 페이지 중 해당 PID가 사용중인 페이지를 사용 해제하고 0으로 초기화합니다. 이때 해당 페이지의 Free Block도 삭제(해제)합니다.
3. Swap 공간에도 마찬가지로 Free SF List를 순차 탐색하여 Swap된 페이지들 중 해당 PID가 사용중이던 페이지를 0으로 초기화하고 해당 페이지의 Free Block도 삭제(해제)합니다. 이 작업에서 Swap된 페이지를 초기화하는 과정에서 디스크에 접근하나, 메모리에 올리지 않고 바로 디스크의 해당 페이지만큼의 영역을 초기화하도록 하였습니다.
4. 현재 실행중이던 프로세스를 참조하는 `current` 변수와 `pdbr` 변수를 NULL로 설정하고, PCB List에서 현재 실행중이던 프로세스의 PCB의 참조를 끊도록 NULL로 설정합니다.
5. 현재 실행중이던 프로세스의 PCB 구조체 인스턴스를 `free()` 함수를 사용해 메모리 해제(삭제)합니다.
6. 작업을 성공했으므로 0을 반환합니다.

## 3. 함수 Design 및 Specification

디버깅을 위한 출력 함수는 제외하고 작성하였습니다.

### 3-1. Queue Operating Functions

**`queue_init`**

| Functionality | 매개변수로 받은 Queue를 동적할당하여 초기화하고, 최대 길이를 설정합니다. |
| --- | --- |
| Parameters | - struct queue **_queue: 초기화할 Queue의 포인터 변수
- int max_length: 해당 Queue 데이터 배열의 최대 길이 |
| Return Value | 없음 |

**`queue_check_empty`**

| Functionality | 매개변수로 받은 Queue의 데이터가 비어있는지 여부를 반환 |
| --- | --- |
| Parameters | - const struct queue *_queue: 참조할 Queue의 포인터 변수 |
| Return Value | 비어있다면 1, 비어있지 않다면 0을 반환 |

**`queue_check_full`**

| Functionality | 매개변수로 받은 Queue의 데이터가 가득 차있는지 여부를 반환 |
| --- | --- |
| Parameters | - const struct queue *_queue: 참조할 Queue의 포인터 변수 |
| Return Value | 가득 차있다면 1, 남은 공간이 있다면 0을 반환 |

**`enqueue`**

| Functionality | 매개변수로 받은 Queue의 데이터에 원소를 enqueue |
| --- | --- |
| Parameters | - const struct queue *_queue: 참조할 Queue의 포인터 변수
- unsigned short item: 큐에 삽입할 원소 (정수) |
| Return Value | 없음 |

**`dequeue`**

| Functionality | 매개변수로 받은 Queue의 데이터에서 FIFO로 top 원소를 dequeue |
| --- | --- |
| Parameters | - const struct queue *_queue: 참조할 Queue의 포인터 변수 |
| Return Value | Queue에서 Dequeue한 원소 (정수) |

### 3-2. Entry Checking Functions

**`check_entry_valid`**

| Functionality | 해당 Entry가 Valid한지 여부를 반환 (Entry의 모든 비트가 0이 아니라면 Valid) |
| --- | --- |
| Parameters | - const unsigned short entry: 검사할 Entry 값 (정수) |
| Return Value | Entry가 Valid하면 1, Invalid하면 0 |

**`check_entry_invalid`**

| Functionality | 해당 Entry가 Invalid한지 여부를 반환 (Entry의 모든 비트가 0이라면 Invalid) |
| --- | --- |
| Parameters | - const unsigned short entry: 검사할 Entry 값 (정수) |
| Return Value | Entry가 Invalid하면 1, Valid하면 0 |

**`check_entry_dirty`**

| Functionality | 해당 Entry에 쓰기 작업이 있었는지 여부를 반환 (Entry의 하위 2번째 비트가 Dirty Bit, Dirty Bit이 1이라면 쓰기 작업이 있었음) |
| --- | --- |
| Parameters | - const unsigned short entry: 검사할 Entry 값 (정수) |
| Return Value | Entry가 Dirty하면 1, 아니면 0 |

**`check_entry_present`**

| Functionality | 해당 Entry가 물리 메모리에 존재하는지 여부를 반환 (Entry의 하위 1번째 비트가 Present Bit, Present Bit이 1이라면 참조하는 페이지가 물리 메모리에 존재) |
| --- | --- |
| Parameters | - const unsigned short entry: 검사할 Entry 값 (정수) |
| Return Value | Entry가 Present하면 1, 아니면 0 |

**`check_entry_swapped`**

| Functionality | 해당 Entry가 Swap-out되어 Swap Space에 존재하는지 여부를 반환 (Entry의 Dirty Bit이 1, Present Bit이 0이라면 Swap-out 상태) |
| --- | --- |
| Parameters | - const unsigned short entry: 검사할 Entry 값 (정수) |
| Return Value | Entry가 Swap-Out 상태면 1, 아니면 0 |

### 3-3. Page Frame Number to Address Translation

**`get_pf_addr`**

| Functionality | 해당 PFN의 물리 메모리 상의 주소를 반환 |
| --- | --- |
| Parameters | - const int pfn: 주소로 변환할 PFN |
| Return Value | 물리 메모리 상의 PFN번째 페이지의 시작 주소 (char*) |

**`get_sf_addr`**

| Functionality | 해당 SFN의 Swap 공간 상의 주소를 반환 |
| --- | --- |
| Parameters | - const int sfn: 주소로 변환할 SFN |
| Return Value | Swap 공간 상의 SFN번째 페이지의 시작 주소 (char*) |

### 3-4. Page Frame Sequential Search and Return

**`find_entry_by_pfn`**

| Functionality | 첫 번째 인자로 들어온 PFN번째 페이지의 Entry 중 pfn_to_find PFN을 가진 Entry의 주소를 찾아 반환합니다. |
| --- | --- |
| Parameters | - unsigned short pfn: Entry를 포함한 페이지 PFN
- unsigned short pfn_to_find: 찾을 Entry가 포함하는 대상인 PFN |
| Return Value | Entry를 찾은 경우 Entry 주소 (unsigned short*), 만약 찾지 못한 경우 NULL |

**`get_sfn_sequential`**

| Functionality | Swap 공간에서 비어있는 페이지의 SFN을 순차 검색으로 찾아 반환합니다. |
| --- | --- |
| Parameters | - int not_sfn: 임시로 할당중이거나 사용을 예약중이어서 새롭게 할당에서 제외할 SFN 번호 |
| Return Value | 순차 검색으로 찾은 비어있는 SFN, 만약 없는 경우 -1을 반환 |

**`get_pfn_sequential`**

| Functionality | 물리 메모리에서 비어있는 페이지의 PFN을 순차 검색으로 찾아 반환합니다. 만약 현재 비어있는 물리 메모리 페이지가 없다면, evict할 페이지를 찾고, evict가 가능한 페이지를 찾은 경우 각 페이지의 조건과 특성에 따라 Swap-out 또는 폐기 작업을 통해 빈 페이지를 만든 후 PFN을 반환합니다. |
| --- | --- |
| Parameters | - int not_evict_pfn: 임시로 할당중이거나 사용을 예약중이어서 새롭게 할당에서 제외할 PFN 번호 |
| Return Value | 순차 검색으로 찾은 비어있는 PFN 혹은 Swapping 작업 후 비어있는 PFN
오류 발생 또는 비어있는 PFN이 없는 경우 -1 반환 |

**`return_sfn`**

| Functionality | 사용중이던 Swap 공간의 SFN 페이지를 반환하여 사용 가능한 상태로 만듭니다. 해당 페이지를 0으로 초기화하고 free_sf_list에서 free block을 삭제(해제)합니다 |
| --- | --- |
| Parameters | - int sfn: 반환할 Swap 공간 페이지의 SFN |
| Return Value | 성공 시 0, 실패 및 오류 발생 시 1 반환 |

**`return_pfn`**

| Functionality | 사용중이던 물리 메모리의 PFN 페이지를 반환하여 사용 가능한 상태로 만듭니다. 해당 페이지를 0으로 초기화하고 free_pf_list에서 free block을 삭제(해제)합니다 |
| --- | --- |
| Parameters | - int pfn: 반환할 물리 메모리 페이지의 PFN |
| Return Value | 성공 시 0, 실패 및 오류 발생 시 1 반환 |

### 3-5. 주요 구현 함수

**`ku_freelist_init`**

| Functionality | 물리 메모리와 Swap 공간을 효율적으로 관리하기 위한 Free List 두 개의 배열(free_pf_list, free_sf_list)을 동적 할당하고 초기화합니다. |
| --- | --- |
| Parameters | 없음 |
| Return Value | 없음 |

**`ku_proc_init`**

| Functionality | 프로세스를 실행하기 위한 준비 작업을 합니다. argv 배열로 넘어온 파일을 읽어 각 프로세스별로 PCB와 Free Block을 할당하고 설정합니다. 
Ready Queue, PF Queue, PCB List 등을 동적 할당하고 초기화합니다. |
| --- | --- |
| Parameters | - int argc: Main 함수 실행 시 넘어온 Command Line Argument의 개수 (공백 구분), 여기서는 사용하지 않음
- char *argv[]: Main 함수 실행 시 넘어온 Command Line Argument, 여기서는 프로세스 정보가 담긴 input 파일의 파일명이 넘어온다고 가정함 |
| Return Value | 성공 시 0, 실패 및 오류 발생 시 1 반환 |

**`ku_scheduler`**

| Functionality | Round Robin 방식에 따라 다음에 실행할 Process를 선택하고, current와 pdbr 변수를 설정합니다. Context Switch가 발생하였다면, 새롭게 실행할 Process에 대해 설정하고, 이전에 실행중이던 프로세스를 Ready Queue에 넣습니다. |
| --- | --- |
| Parameters | - unsigned short pid: 현재 실행중인 Process의 PID |
| Return Value | 성공 시 0, 실패 및 오류 발생 또는 실행할 프로세스가 없는 경우 1 반환 |

**`ku_pgfault_handler`**

| Functionality | CPU에서 주소 변환 시 Page Fault가 발생한 경우 Page Fault를 해결하기 위해 Mutli-Level Page Table 알고리즘으로 각 페이지를 적절하게 할당하여 주소 변환이 정상적으로 이루어질 수 있도록 합니다.  |
| --- | --- |
| Parameters | - unsigned short va: 변환 시 Page Fault가 발생한 가상 주소 |
| Return Value | 성공 시 0, 실패 및 오류 발생 시 1 반환 |

**`ku_proc_exit`**

| Functionality | 매개변수로 받은 PID를 종료 처리합니다. 해당 프로세스의 PCB를 메모리 해제하고, 사용중이었던 물리 메모리와 Swap 공간 상의 Page Frame들을 반환합니다. |
| --- | --- |
| Parameters | - unsigned short pid: 종료할 Process의 PID |
| Return Value | 성공 시 0, 실패 및 오류 발생 시 1 반환 |

## 4. 테스트 및 실행 결과

### 4-1. Page Fault Handler 케이스별 Unit Test

Page Fault Handler의 각 케이스(A-1, A-2, B-1, B-2)를 테스트하기 위해 Single Process 상황에서 물리 메모리를 사전 설정하고 Page Fault Handler를 호출하여 유닛 테스트를 진행하였고 검증하였습니다.

**Case A-1) Page Table이 Swap-out되었고, Entry들이 모두 Swap-out된 케이스**

Page Directory → PFN 0

Page Table (swap-out) → SFN 1

Page Table Entry (idx 0) → Page SFN 2

Page Table Entry (idx 1) → Page SFN 3

→ 위 상황에서 `va` 40을 접근

**Case A-2) Page Table이 Swap-Out 되었고, 접근하고자 하는 Entry가 Invalid**

Page Directory → PFN 0

Page Table (swap-out) → SFN 1

Page Table Entry (idx 0) → Invalid (0)

→ 위 상황에서 `va` 40을 접근

**Case B-1) Page Table은 Valid, Page가 Swap-out**

Page Directory → PFN 0

Page Table → PFN 1

Page Table Entry (idx 0) → Page SFN 1

→ 위 상황에서 `va` 40을 접근

**Case B-2) Page Table은 Valid, Page Table Entry가 Invalid (Mapping X)**

Page Directory → PFN 0

Page Table → PFN 1

Page Table Entry (idx 0) → Invalid (0)

→ 위 상황에서 `va` 40을 접근

### 4-2. Single Process, No Swap

```
0 proc1.txt
```

<img width="120px" src="https://github.com/leehe228/OS_kumoo/assets/37548919/6aeafb2d-66b3-460d-a886-11605eb3ed42" alt="">


### 4-3. Multi Process, No Swap

```
0 proc1.txt
1 proc2.txt
2 proc2.txt
```

<img width="120px" src="https://github.com/leehe228/OS_kumoo/assets/37548919/404a9485-3f08-4161-989d-74851d208afa" alt="">


### 4-4. Multi Process, Swapping

테스트를 위해 `pfnum`을 4로 줄여서 실험하였습니다.

```
0 proc2.txt
1 proc1.txt
2 proc2.txt
```

<img width="120px" src="https://github.com/leehe228/OS_kumoo/assets/37548919/18113e4a-7215-4f1e-900f-2250f7ee2aef" alt="">


PID 0 프로세스의 경우, 4개의 물리 메모리 Page Frame 중 3개는 Page Directory에 할당되어 있고, 나머지 1개는 Page Table용으로 예약된 상태이므로, 쓰기 작업을 위한 Page를 할당하기 위해 evict할 수 있는 Page가 없으므로 프로세스가 종료되었습니다.

