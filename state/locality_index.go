/*
   Copyright 2022 Erigon contributors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package state

import (
	"bytes"
	"container/heap"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/ledgerwatch/erigon-lib/common/assert"
	"github.com/ledgerwatch/erigon-lib/common/dbg"
	"github.com/ledgerwatch/erigon-lib/common/dir"
	"github.com/ledgerwatch/erigon-lib/kv/bitmapdb"
	"github.com/ledgerwatch/erigon-lib/recsplit"
	"github.com/ledgerwatch/log/v3"
)

const LocalityIndexUint64Limit = 64 //bitmap spend 1 bit per file, stored as uint64

// LocalityIndex - has info in which .ef or .kv files exists given key
// Format: key -> bitmap(step_number_list)
// step_number_list is list of .ef files where exists given key
type LocalityIndex struct {
	filenameBase    string
	dir, tmpdir     string // Directory where static files are created
	aggregationStep uint64 // immutable

	file *filesItem
	bm   *bitmapdb.FixedSizeBitmaps

	roFiles  atomic.Pointer[ctxItem]
	roBmFile atomic.Pointer[bitmapdb.FixedSizeBitmaps]
	logger   log.Logger

	noFsync bool // fsync is enabled by default, but tests can manually disable
}

func NewLocalityIndex(
	dir, tmpdir string,
	aggregationStep uint64,
	filenameBase string,
	logger log.Logger,
) (*LocalityIndex, error) {
	li := &LocalityIndex{
		dir:             dir,
		tmpdir:          tmpdir,
		aggregationStep: aggregationStep,
		filenameBase:    filenameBase,
		logger:          logger,
	}
	return li, nil
}
func (li *LocalityIndex) closeWhatNotInList(fNames []string) {
	if li == nil || li.bm == nil {
		return
	}

	for _, protectName := range fNames {
		if li.bm.FileName() == protectName {
			return
		}
	}
	li.closeFiles()
}

func (li *LocalityIndex) OpenList(fNames []string) error {
	if li == nil {
		return nil
	}
	li.closeWhatNotInList(fNames)
	_ = li.scanStateFiles(fNames)
	if err := li.openFiles(); err != nil {
		return fmt.Errorf("LocalityIndex.openFiles: %s, %w", li.filenameBase, err)
	}
	return nil
}

func (li *LocalityIndex) scanStateFiles(fNames []string) (uselessFiles []*filesItem) {
	if li == nil {
		return nil
	}

	re := regexp.MustCompile("^" + li.filenameBase + ".([0-9]+)-([0-9]+).li$")
	var err error
	for _, name := range fNames {
		subs := re.FindStringSubmatch(name)
		if len(subs) != 3 {
			if len(subs) != 0 {
				li.logger.Warn("File ignored by inverted index scan, more than 3 submatches", "name", name, "submatches", len(subs))
			}
			continue
		}
		var startStep, endStep uint64
		if startStep, err = strconv.ParseUint(subs[1], 10, 64); err != nil {
			li.logger.Warn("File ignored by inverted index scan, parsing startTxNum", "error", err, "name", name)
			continue
		}
		if endStep, err = strconv.ParseUint(subs[2], 10, 64); err != nil {
			li.logger.Warn("File ignored by inverted index scan, parsing endTxNum", "error", err, "name", name)
			continue
		}
		if startStep > endStep {
			li.logger.Warn("File ignored by inverted index scan, startTxNum > endTxNum", "name", name)
			continue
		}

		if startStep != 0 {
			li.logger.Warn("LocalityIndex must always starts from step 0")
			continue
		}
		if endStep > StepsInBiggestFile*LocalityIndexUint64Limit {
			li.logger.Warn("LocalityIndex does store bitmaps as uint64, means it can't handle > 2048 steps. But it's possible to implement")
			continue
		}

		startTxNum, endTxNum := startStep*li.aggregationStep, endStep*li.aggregationStep
		if li.file == nil {
			li.file = newFilesItem(startTxNum, endTxNum, li.aggregationStep)
			li.file.frozen = false // LocalityIndex files are never frozen
		} else if li.file.endTxNum < endTxNum {
			uselessFiles = append(uselessFiles, li.file)
			li.file = newFilesItem(startTxNum, endTxNum, li.aggregationStep)
			li.file.frozen = false // LocalityIndex files are never frozen
		}
	}
	return uselessFiles
}

func (li *LocalityIndex) openFiles() (err error) {
	if li == nil || li.file == nil {
		return nil
	}

	fromStep, toStep := li.file.startTxNum/li.aggregationStep, li.file.endTxNum/li.aggregationStep
	if li.bm == nil {
		dataPath := filepath.Join(li.dir, fmt.Sprintf("%s.%d-%d.l", li.filenameBase, fromStep, toStep))
		if dir.FileExist(dataPath) {
			li.bm, err = bitmapdb.OpenFixedSizeBitmaps(dataPath, int((toStep-fromStep)/StepsInBiggestFile))
			if err != nil {
				return err
			}
		}
	}
	if li.file.index == nil {
		idxPath := filepath.Join(li.dir, fmt.Sprintf("%s.%d-%d.li", li.filenameBase, fromStep, toStep))
		if dir.FileExist(idxPath) {
			li.file.index, err = recsplit.OpenIndex(idxPath)
			if err != nil {
				return fmt.Errorf("LocalityIndex.openFiles: %w, %s", err, idxPath)
			}
		}
	}
	li.reCalcRoFiles()
	return nil
}

func (li *LocalityIndex) closeFiles() {
	if li == nil {
		return
	}
	if li.file != nil && li.file.index != nil {
		li.file.index.Close()
		li.file = nil
	}
	if li.bm != nil {
		li.bm.Close()
		li.bm = nil
	}
}
func (li *LocalityIndex) reCalcRoFiles() {
	if li == nil || li.file == nil {
		return
	}
	li.roFiles.Store(&ctxItem{
		startTxNum: li.file.startTxNum,
		endTxNum:   li.file.endTxNum,
		i:          0,
		src:        li.file,
	})
	li.roBmFile.Store(li.bm)
}

func (li *LocalityIndex) MakeContext() *ctxLocalityIdx {
	if li == nil {
		return nil
	}
	x := &ctxLocalityIdx{
		file:            li.roFiles.Load(),
		bm:              li.roBmFile.Load(),
		aggregationStep: li.aggregationStep,
	}
	if x.file != nil && x.file.src != nil {
		x.file.src.refcount.Add(1)
	}
	return x
}

func (lc *ctxLocalityIdx) Close() {
	if lc == nil || lc.file == nil || lc.file.src == nil {
		return
	}
	refCnt := lc.file.src.refcount.Add(-1)
	if refCnt == 0 && lc.file.src.canDelete.Load() {
		closeLocalityIndexFilesAndRemove(lc)
	}
}

func closeLocalityIndexFilesAndRemove(i *ctxLocalityIdx) {
	if i.file.src != nil {
		i.file.src.closeFilesAndRemove()
		i.file.src = nil
	}
	if i.bm != nil {
		if err := i.bm.Close(); err != nil {
			log.Log(dbg.FileCloseLogLevel, "unmap", "err", err, "file", i.bm.FileName(), "stack", dbg.Stack())
		}
		if err := os.Remove(i.bm.FilePath()); err != nil {
			log.Log(dbg.FileCloseLogLevel, "os.Remove", "err", err, "file", i.bm.FileName(), "stack", dbg.Stack())
		}
		i.bm = nil
	}
}

func (li *LocalityIndex) Close() {
	li.closeWhatNotInList([]string{})
	li.reCalcRoFiles()
}
func (li *LocalityIndex) Files() (res []string) { return res }
func (li *LocalityIndex) NewIdxReader() *recsplit.IndexReader {
	if li != nil && li.file != nil && li.file.index != nil {
		return recsplit.NewIndexReader(li.file.index)
	}
	return nil
}

// LocalityIndex return exactly 2 file (step)
// prevents searching key in many files
func (lc *ctxLocalityIdx) lookupIdxFiles(key []byte, fromTxNum uint64) (exactShard1, exactShard2 uint64, lastIndexedTxNum uint64, ok1, ok2 bool) {
	if lc == nil || lc.bm == nil {
		return 0, 0, 0, false, false
	}
	if lc.reader == nil {
		lc.reader = recsplit.NewIndexReader(lc.file.src.index)
	}

	if fromTxNum >= lc.file.endTxNum {
		return 0, 0, fromTxNum, false, false
	}

	fromFileNum := fromTxNum / lc.aggregationStep / StepsInBiggestFile
	fn1, fn2, ok1, ok2, err := lc.bm.First2At(lc.reader.Lookup(key), fromFileNum)
	if err != nil {
		panic(err)
	}
	return fn1 * StepsInBiggestFile, fn2 * StepsInBiggestFile, lc.file.endTxNum, ok1, ok2
}

// indexedTo - [from, to)
func (lc *ctxLocalityIdx) indexedTo() uint64 {
	if lc == nil || lc.bm == nil {
		return 0
	}
	return lc.file.endTxNum
}

// lookupLatest return latest file (step)
// prevents searching key in many files
func (lc *ctxLocalityIdx) lookupLatest(key []byte) (latestShard, lastIndexedTxNum uint64, ok bool) {
	if lc == nil || lc.bm == nil {
		return 0, 0, false
	}
	if lc.reader == nil {
		lc.reader = recsplit.NewIndexReader(lc.file.src.index)
	}
	fn1, ok1, err := lc.bm.LastAt(lc.reader.Lookup(key))
	if err != nil {
		panic(err)
	}
	return fn1 * StepsInBiggestFile, lc.file.endTxNum, ok1
}

func (li *LocalityIndex) exists(step uint64) bool {
	return dir.FileExist(filepath.Join(li.dir, fmt.Sprintf("%s.%d-%d.li", li.filenameBase, 0, step)))
}
func (li *LocalityIndex) missedIdxFiles(ii *HistoryContext) (toStep uint64, idxExists bool) {
	if len(ii.files) == 0 {
		return 0, true
	}
	var item *ctxItem
	for i := len(ii.files) - 1; i >= 0; i-- {
		if ii.files[i].src.frozen {
			item = &ii.files[i]
			break
		}
	}
	if item != nil {
		toStep = item.endTxNum / li.aggregationStep
	}
	fName := fmt.Sprintf("%s.%d-%d.li", li.filenameBase, 0, toStep)
	return toStep, dir.FileExist(filepath.Join(li.dir, fName))
}
func (li *LocalityIndex) buildFiles(ctx context.Context, toStep uint64, makeIter func() *LocalityIterator) (files *LocalityIndexFiles, err error) {
	logEvery := time.NewTicker(30 * time.Second)
	defer logEvery.Stop()

	fromStep := uint64(0)
	count := 0
	it := makeIter()
	for it.HasNext() {
		_, _ = it.Next()
		count++
	}

	fName := fmt.Sprintf("%s.%d-%d.li", li.filenameBase, fromStep, toStep)
	idxPath := filepath.Join(li.dir, fName)
	filePath := filepath.Join(li.dir, fmt.Sprintf("%s.%d-%d.l", li.filenameBase, fromStep, toStep))

	rs, err := recsplit.NewRecSplit(recsplit.RecSplitArgs{
		KeyCount:   count,
		Enums:      false,
		BucketSize: 2000,
		LeafSize:   8,
		TmpDir:     li.tmpdir,
		IndexFile:  idxPath,
	}, li.logger)
	if err != nil {
		return nil, fmt.Errorf("create recsplit: %w", err)
	}
	defer rs.Close()
	rs.LogLvl(log.LvlTrace)
	if li.noFsync {
		rs.DisableFsync()
	}
	i := uint64(0)
	for {
		dense, err := bitmapdb.NewFixedSizeBitmapsWriter(filePath, int(it.FilesAmount()), uint64(count), li.logger)
		if err != nil {
			return nil, err
		}
		defer dense.Close()
		if li.noFsync {
			dense.DisableFsync()
		}

		it = makeIter()
		for it.HasNext() {
			k, inFiles := it.Next()
			//fmt.Printf("buld: %x, %d, %d\n", k, i, inFiles)
			if err := dense.AddArray(i, inFiles); err != nil {
				return nil, err
			}
			if err = rs.AddKey(k, i); err != nil {
				return nil, err
			}
			i++

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-logEvery.C:
				li.logger.Info("[LocalityIndex] build", "name", li.filenameBase, "progress", fmt.Sprintf("%.2f%%", 50+it.Progress()/2))
			default:
			}
		}

		if err := dense.Build(); err != nil {
			return nil, err
		}

		if err = rs.Build(); err != nil {
			if rs.Collision() {
				li.logger.Debug("Building recsplit. Collision happened. It's ok. Restarting...")
				rs.ResetNextSalt()
			} else {
				return nil, fmt.Errorf("build idx: %w", err)
			}
		} else {
			break
		}
	}

	idx, err := recsplit.OpenIndex(idxPath)
	if err != nil {
		return nil, err
	}
	bm, err := bitmapdb.OpenFixedSizeBitmaps(filePath, int(it.FilesAmount()))
	if err != nil {
		return nil, err
	}
	return &LocalityIndexFiles{index: idx, bm: bm}, nil
}

func (li *LocalityIndex) integrateFiles(sf LocalityIndexFiles, txNumFrom, txNumTo uint64) {
	if li.file != nil {
		li.file.canDelete.Store(true)
	}
	li.file = &filesItem{
		startTxNum: txNumFrom,
		endTxNum:   txNumTo,
		index:      sf.index,
		frozen:     false,
	}
	li.bm = sf.bm
	li.reCalcRoFiles()
}

func (li *LocalityIndex) BuildMissedIndices(ctx context.Context, toStep uint64, makeIter func() *LocalityIterator) error {
	fromStep := uint64(0)
	f, err := li.buildFiles(ctx, toStep, makeIter)
	if err != nil {
		return err
	}
	li.integrateFiles(*f, fromStep*li.aggregationStep, toStep*li.aggregationStep)
	return nil
}

type LocalityIndexFiles struct {
	index *recsplit.Index
	bm    *bitmapdb.FixedSizeBitmaps
}

func (sf LocalityIndexFiles) Close() {
	if sf.index != nil {
		sf.index.Close()
	}
	if sf.bm != nil {
		sf.bm.Close()
	}
}

type LocalityIterator struct {
	aggStep           uint64
	compressVals      bool
	h                 ReconHeapOlderFirst
	v, nextV, vBackup []uint64
	k, nextK, kBackup []byte
	progress          uint64

	totalOffsets, filesAmount uint64
}

func (si *LocalityIterator) advance() {
	for si.h.Len() > 0 {
		top := heap.Pop(&si.h).(*ReconItem)
		key := top.key
		var offset uint64
		if si.compressVals {
			offset = top.g.Skip()
		} else {
			offset = top.g.SkipUncompressed()
		}
		si.progress += offset - top.lastOffset
		top.lastOffset = offset
		inStep := uint32(top.startTxNum / si.aggStep)
		if top.g.HasNext() {
			top.key, _ = top.g.NextUncompressed()
			heap.Push(&si.h, top)
		}

		inFile := uint64(inStep / StepsInBiggestFile)

		if si.k == nil {
			si.k = key
			si.v = append(si.v, inFile)
			continue
		}

		if !bytes.Equal(key, si.k) {
			si.nextV, si.v = si.v, si.nextV[:0]
			si.nextK = si.k

			si.v = append(si.v, inFile)
			si.k = key
			return
		}
		si.v = append(si.v, inFile)
	}
	si.nextV, si.v = si.v, si.nextV[:0]
	si.nextK = si.k
	si.k = nil
}

func (si *LocalityIterator) HasNext() bool { return si.nextK != nil }
func (si *LocalityIterator) Progress() float64 {
	return (float64(si.progress) / float64(si.totalOffsets)) * 100
}
func (si *LocalityIterator) FilesAmount() uint64 { return si.filesAmount }

func (si *LocalityIterator) Next() ([]byte, []uint64) {
	//if hi.err != nil {
	//	return nil, nil, hi.err
	//}
	//hi.limit--

	// Satisfy iter.Dual Invariant 2
	si.nextK, si.kBackup, si.nextV, si.vBackup = si.kBackup, si.nextK, si.vBackup, si.nextV
	si.advance()
	return si.kBackup, si.vBackup
}

func (ic *InvertedIndexContext) iterateKeysLocality(uptoTxNum uint64) *LocalityIterator {
	si := &LocalityIterator{aggStep: ic.ii.aggregationStep, compressVals: false}
	for _, item := range ic.files {
		if !item.src.frozen || item.startTxNum > uptoTxNum {
			continue
		}
		if assert.Enable {
			if (item.endTxNum-item.startTxNum)/si.aggStep != StepsInBiggestFile {
				panic(fmt.Errorf("frozen file of small size: %s", item.src.decompressor.FileName()))
			}
		}
		g := item.src.decompressor.MakeGetter()
		if g.HasNext() {
			key, offset := g.NextUncompressed()

			heapItem := &ReconItem{startTxNum: item.startTxNum, endTxNum: item.endTxNum, g: g, txNum: ^item.endTxNum, key: key, startOffset: offset, lastOffset: offset}
			heap.Push(&si.h, heapItem)
		}
		si.totalOffsets += uint64(g.Size())
		si.filesAmount++
	}
	si.advance()
	return si
}

func (dc *DomainContext) iterateKeysLocality(uptoTxNum uint64) *LocalityIterator {
	si := &LocalityIterator{aggStep: dc.d.aggregationStep, compressVals: dc.d.compressVals}
	for _, item := range dc.files {
		if !item.src.frozen || item.startTxNum > uptoTxNum {
			continue
		}
		if assert.Enable {
			if (item.endTxNum-item.startTxNum)/si.aggStep != StepsInBiggestFile {
				panic(fmt.Errorf("frozen file of small size: %s", item.src.decompressor.FileName()))
			}
		}
		g := item.src.decompressor.MakeGetter()
		if g.HasNext() {
			key, offset := g.NextUncompressed()
			heapItem := &ReconItem{startTxNum: item.startTxNum, endTxNum: item.endTxNum, g: g, txNum: ^item.endTxNum, key: key, startOffset: offset, lastOffset: offset}
			heap.Push(&si.h, heapItem)
		}
		si.totalOffsets += uint64(g.Size())
		si.filesAmount++
	}
	si.advance()
	return si
}
