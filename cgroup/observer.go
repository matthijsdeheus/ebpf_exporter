package cgroup

import (
	"sync"
	"time"
)

const gcInterval = time.Minute
const gcTTL = time.Minute * 10

type resolved struct {
	dead time.Time // time of last use, zero if the path is alive
	path string
}

// observer keeps track of inode -> path mappings and removes the ones that are no longer
// present after they exceed their garbage collection time to live.
type observer struct {
	lock        sync.Mutex
	inodeToPath map[int]*resolved
	pathToInode map[string]int
}

func newObserver(initial map[int]string) *observer {
	observer := observer{
		lock:        sync.Mutex{},
		inodeToPath: map[int]*resolved{},
		pathToInode: map[string]int{},
	}

	for inode, name := range initial {
		observer.add(inode, name)
	}

	go func() {
		for {
			time.Sleep(gcInterval)
			observer.gc()
		}
	}()

	return &observer
}

func (o *observer) gc() {
	o.lock.Lock()
	defer o.lock.Unlock()

	now := time.Now()

	remove := []int{}

	for inode, r := range o.inodeToPath {
		if r.dead.IsZero() {
			continue
		}

		if now.Sub(r.dead) > gcTTL {
			remove = append(remove, inode)
		}
	}

	for _, inode := range remove {
		path := o.inodeToPath[inode].path
		delete(o.inodeToPath, inode)
		delete(o.pathToInode, path)
	}
}

func (o *observer) add(inode int, path string) {
	o.lock.Lock()
	defer o.lock.Unlock()

	r := &resolved{
		dead: time.Time{},
		path: path,
	}

	o.inodeToPath[inode] = r
	o.pathToInode[path] = inode
}

func (o *observer) remove(path string) {
	o.lock.Lock()
	defer o.lock.Unlock()

	inode, ok := o.pathToInode[path]
	if !ok {
		return
	}

	r := o.inodeToPath[inode]
	r.dead = time.Now()
}

func (o *observer) lookup(inode int) string {
	o.lock.Lock()
	defer o.lock.Unlock()

	r, ok := o.inodeToPath[inode]
	if !ok {
		return ""
	}

	if !r.dead.IsZero() {
		r.dead = time.Now()
	}

	return r.path
}
