searchState.loadedDescShard("mito2", 1, "Calls <code>U::from(self)</code>.\nThe memory usage of the index creator.\nCreates a new <code>InvertedIndexer</code>. Should ensure that the …\nStatistics of index creation.\nThe provider of intermediate files.\nUpdates index with a batch of rows. Garbage will be …\nReusable buffer for encoding index values.\nA <code>PuffinFileAccessor</code> implementation that uses an object …\nA factory for creating <code>SstPuffinManager</code> instances.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreates a new <code>PuffinManagerFactory</code> instance.\nThe stager used by the puffin manager.\nThe size of the write buffer used to create object store.\nStage of the index creation process.\nStatistics for index creation. Flush metrics when dropped.\n<code>TimerGuard</code> is a RAII struct that ensures elapsed time is …\nReturns byte count.\nNumber of bytes in the index.\nAccumulated elapsed time for the cleanup stage.\nAccumulated elapsed time for the index finish stage.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nIncreases the byte count of the index creation statistics.\nIncreases the row count of the index creation statistics.\nIndex type.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreates a new <code>TimerGuard</code>,\nStarts timing the cleanup stage, returning a <code>TimerGuard</code> to …\nStarts timing the finish stage, returning a <code>TimerGuard</code> to …\nStarts timing the update stage, returning a <code>TimerGuard</code> to …\nReturns row count.\nNumber of rows in the index.\nAccumulated elapsed time for the index update stage.\nA guard that increments a counter when dropped.\nA wrapper around <code>AsyncRead</code> that adds instrumentation for …\nA wrapper around <code>AsyncWrite</code> that adds instrumentation for …\nImplements <code>RangeReader</code> for <code>ObjectStore</code> and record metrics.\nA wrapper around <code>ObjectStore</code> that adds instrumentation for …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nIncrement the counter by <code>n</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nProxies to <code>ObjectStore::list</code>.\nCreate a new <code>CounterGuard</code>.\nCreate a new <code>InstrumentedStore</code>.\nCreate a new <code>InstrumentedAsyncRead</code>.\nCreate a new <code>InstrumentedAsyncWrite</code>.\nThe underlying object store.\nReturns an <code>InstrumentedRangeReader</code> for the given path. …\nReturns an <code>InstrumentedAsyncRead</code> for the given path. …\nProxies to <code>ObjectStore::remove_all</code>.\nSet the size of the write buffer.\nThe size of the write buffer.\nReturns an <code>InstrumentedAsyncWrite</code> for the given path. …\nReturns the path of the index file in the object store: …\nReturns the path of the SST file in the object store: …\nDefault batch size to read parquet files.\nDefault row group size for parquet files.\nKey of metadata in parquet SST.\nParquet SST info returned by the writer.\nParquet write options.\nSST file id.\nFile Meta Data\nStructs and functions for reading ranges from a parquet …\nFile size in bytes.\nFormat to store in parquet.\nReturns the argument unchanged.\nReturns the argument unchanged.\nIndex Meta Data\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nNumber of row groups\nNumber of rows.\nParquet page reader.\nParquet reader.\nPorts private structs from parquet crate.\nRow group size.\nStatistics of parquet SSTs.\nTime range of the SST. The timestamps have the same time …\nBuffer size for async writer.\nParquet writer.\nA range of a parquet SST. Now it is a row group. We can …\nContext shared by ranges of the same parquet SST.\nCommon fields for a range to read and filter batches.\nBase of the context.\nDecoder for primary keys\nReturns the helper to compat batches.\nReturns the helper to compat batches.\nOptional helper to compat batches.\nShared context.\nReturns the file handle of the file range.\nReturns the path of the file to read.\nReturns filters pushed down.\nFilters pushed down.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreates a new FileRangeContext.\nCreates a new FileRange.\nTRY THE BEST to perform pushed down predicate precisely on …\nTRY THE BEST to perform pushed down predicate precisely on …\nReturns the format helper.\nHelper to read the SST.\nReturns a reader to read the FileRange.\nReturns the reader builder.\nRow group reader builder for the file.\nIndex of the row group in the SST.\nRow selection for the row group. <code>None</code> means all rows.\nReturns true if FileRange selects all rows in row group.\nSets the <code>CompatBatch</code> to the context.\nNumber of columns that have fixed positions.\nArrow array type for the primary key dictionary.\nHelper for reading the SST format.\nHelper for writing the SST format.\nGets the arrow schema to store in parquet.\nGets the arrow schema of the SST file.\nSST file schema.\nSST file schema.\nReturns null counts of specific non-tag columns.\nReturns min/max values of specific non-tag columns.\nConvert <code>batch</code> to a arrow record batch to store in parquet.\nConvert a arrow record batch into <code>batches</code>.\nField column id to its index in <code>schema</code> (SST schema). In …\nField column id to their index in the projected schema ( …\nIndex of a field column by its column id.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet fields from <code>record_batch</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns max values of specific column in row groups.\nGets the metadata of the SST.\nReturns min values of specific column in row groups.\nCreates a new helper.\nCreates a helper with existing <code>metadata</code> and <code>column_ids</code> to …\nCreates a new array for specific <code>primary_key</code>.\nReturns null counts of specific column in row groups.\nGets the min/max time index of the row group from the …\nCompute offsets of different primary keys in the array.\nIndex in SST of the primary key.\nGets sorted projection indices to read.\nIndices of columns to read from the SST. It contains all …\nReturns min/max values of specific tag.\nIndex in SST of the time index.\nSet override sequence.\nAsynchronously fetches byte ranges from an object store.\nParses column orders from Thrift definition. If no column …\nConvert format::FileMetaData to ParquetMetaData\nThe estimated size of the footer and metadata need to read …\nLoad the metadata of parquet file in an async way.\nReturns the argument unchanged.\nGet the size of parquet file.\nCalls <code>U::from(self)</code>.\nAsync load the metadata of parquet file.\nCreate a new parquet metadata loader.\nA reader that reads all pages from a cache.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nReturns a new reader from pages of a column in a row group.\nGet PageMetadata from <code>page</code>.\nCached pages.\nThe reader is exhausted.\nParquet batch reader to read our SST format.\nParquet SST reader builder.\nThe reader is reading a row group.\nMetrics of filtering rows groups and rows.\nParquet reader metrics.\nThe state of a ParquetReader.\nRowGroupReader that reads from [FileRange].\nReader to read a row group of a parquet file.\nBuilder to build a ParquetRecordBatchReader for a row …\nRowGroupReaderContext represents the fields that cannot be …\nContext to evaluate the column filter.\nBuffered batches to return.\nBuffered batches to return.\nAttaches the bloom filter index applier to the builder.\nBuilds a ParquetReader.\nBuilds a ParquetRecordBatchReader to read the row group at …\nDuration to build the parquet reader.\nBuilds a FileRangeContext and collects row groups to read.\nAttaches the cache to the builder.\nStrategy to cache SST data.\nCache.\nReturns the column id.\nId of the column to evaluate.\nFile range context.\nContext of RowGroupReader so adapts to different …\nContext of RowGroupReader so adapts to different …\nCreates a new reader.\nReturns the data type of the column.\nThe data type of the column.\nAttaches the expected metadata to the builder.\nExpected metadata of the region while reading the SST. …\nTries to fetch next RecordBatch from the reader.\nField levels to read.\nSST directory.\nHandle of the file to read.\nSST file to read.\nPath of the file to read.\nPath of the file.\nReturns the filter to evaluate.\nFilter to evaluate.\nFiltered row groups and rows metrics.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nAttaches the fulltext index applier to the builder.\nDecodes region metadata from key value.\nGroups row IDs into row groups, with each group’s row …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nAttaches the inverted index applier to the builder.\nIndex appliers.\nAdds <code>other</code> metrics to this metrics.\nAdds <code>other</code> metrics to this metrics.\nReturns the metadata of the SST.\nReturns the metrics of the reader.\nGets the metrics.\nLocal scan metrics.\nLocal scan metrics.\nReturns a new ParquetReaderBuilder to read specific SST.\nCreates a new reader.\nCreates a new reader from file range.\nCreates a context for the <code>expr</code>.\nReturns the next Batch.\nNumber of batches decoded.\nNumber of record batches read.\nNumber of rows read.\nObject store as an Operator.\nReports metrics.\nReports total rows.\nMetadata of the parquet file.\nAttaches the predicate to the builder.\nPredicate to push down.\nAttaches the projection to the builder.\nMetadata of columns to read.\nProjection mask.\nPrunes row groups by fulltext index. Returns <code>true</code> if the …\nApplies index to prune row groups.\nPrunes row groups by min-max index.\nPrunes row groups by ranges. The <code>ranges_in_row_groups</code> is …\nPrunes row groups by rows. The <code>rows_in_row_groups</code> is like …\nGets ReadFormat of underlying reader.\nReads parquet metadata of specific file.\nInner parquet reader.\nInner parquet reader.\nReader of current row group.\nNumber of row groups filtered by bloom filter index.\nNumber of row groups filtered by fulltext index.\nNumber of row groups filtered by inverted index.\nNumber of row groups filtered by min-max index.\nNumber of row groups before filtering.\nIndices of row groups to read, along with their respective …\nComputes row groups to read, along with their respective …\nNumber of rows in row group filtered by bloom filter index.\nNumber of rows in row group filtered by fulltext index.\nNumber of rows in row group filtered by inverted index.\nNumber of rows filtered by precise filter.\nNumber of rows in row group before filtering.\nDuration to scan the reader.\nReturns the semantic type of the column.\nSemantic type of the column.\nAn in-memory column chunk\nImplements <code>PageIterator</code> for a single column chunk, …\nFull column chunk and its offset\nAn in-memory collection of column chunks\nColumn chunk data representing only a subset of data pages\nAssigns uncompressed chunk binary data to …\nReturns whether we cache uncompressed pages for the column.\nCompressed page of each column.\nCreates a page reader to read column at <code>i</code>.\nCreate PageReader from RowGroupBase::column_chunks\nRow group level cached pages for each column.\nCreates a new InMemoryRowGroup by <code>row_group_idx</code>.\nFetches the necessary column data into memory\nTry to fetch data from WriteCache, if not in WriteCache, …\nFetches pages for columns if cache is enabled. If the page …\nFetches data from write cache. Returns <code>None</code> if the data is …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nObject store.\nSet of data pages included in this sparse chunk. Each …\nLength of the full column chunk\nHelper function to either add a new <code>RowSelector</code> to …\nIntersects two <code>RowSelection</code>s.\nConverts an iterator of row ranges into a <code>RowSelection</code> by …\nConverts an iterator of sorted row IDs into a <code>RowSelection</code>.\nStatistics for pruning row groups.\nReturns the column id of specific column name if we need …\nThe metadata of the region. It contains the schema a query …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCreates a new statistics to prune specific <code>row_groups</code>.\nHelper to read the SST.\nMetadata of SST row groups.\nParquet SST writer.\nWorkaround for AsyncArrowWriter does not provide a method …\nCurrent active file id.\nCurrent active indexer.\nCustomizes per-column config according to schema and maybe …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nIndexer build that can create indexer for multiple files.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nRegion metadata of the source and the target SST.\nCreates a new parquet SST writer.\nNumber of rows fetched.\nPath provider that creates SST and index file paths …\nTime range of fetched batches.\nIterates source and writes all rows to Parquet file.\nMetadata of files in the same SST level.\nA version of all SSTs in a region.\nAdd files to the version.\nHandles of SSTs in this level.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns expired SSTs from current level.\nReturns SST index files’space occupied in current …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nLevel number.\nReturns a slice to metadatas of all levels.\nSST metadata organized by levels.\nMarks all SSTs in this version as deleted.\nReturns a new SstVersion.\nReturns an empty meta of specific <code>level</code>.\nReturns the number of rows in SST files. For historical …\nRemove files from the version.\nReturns SST data files’space occupied in current version.\nDefault implementation of the time provider based on std.\nTrait to get current time and deal with durations.\nReturns current time in millis.\nReturns millis elapsed since specify time.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nComputes the actual duration to wait from an expected one.\nWAL entry id.\nWrite ahead log.\nA stream that yields tuple of WAL entry id and …\nWAL batch writer.\nAdd a wal entry for specific region to the writer’s …\nEntries to write.\nBuffer to encode WAL entry.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreates a new Wal from the log store.\nMark entries whose ids <code>&lt;= last_id</code> as deleted.\nReturns a [OnRegionOpened] function.\nProviders of regions being written into.\nScan entries of specific region starting from <code>start_id</code> …\nLog store of the WAL.\nThe underlying log store.\nReturns a WalEntryReader\nWrite all buffered entries to the WAL.\nReturns a writer to write to the WAL.\nThe default buffer size of the Entry receiver.\nWalEntryDistributor distributes Wal entries to specific …\nReceives the Wal entries from WalEntryDistributor.\nWaits for the arg from the WalEntryReader.\nSends the <code>start_id</code> to the WalEntryDistributor.\nReturns WalEntryDistributor and batch WalEntryReceivers.\nDistributes entries to specific WalEntryReceivers based on …\nReceives the Entry from the WalEntryDistributor.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nSends Entry to receivers based on RegionId\nA Reader reads the [RawEntry] from RawEntryReader and …\nWalEntryReader provides the ability to read and decode …\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nA stream that yields Entry.\nImplement the RawEntryReader for the LogStore.\nRawEntryReader provides the ability to read Entry from the …\nA RawEntryReader reads [RawEntry] belongs to a specific …\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nInterval to check whether regions should flush.\nMax delay to check region periodical tasks.\nWorker to write and alter regions bound to it.\nBackground worker loop to handle requests.\nBuffer for stalled write requests.\nA fixed size group of RegionWorkers.\nIdentifier for a worker.\nWrapper that only calls event listener in tests.\nWorker start config.\nAppends stalled requests.\nReturns cache of the group.\nCache.\nCache.\nCleans up the worker.\nCompaction background job pool.\nScheduler for compaction tasks.\nEngine config.\nRegions that are not yet fully dropped.\nEstimated size of all stalled requests.\nFlush background job pool.\nFlushes regions periodically.\nWatch channel receiver to wait for background flush job.\nWatch channel receiver to wait for background flush job.\nFinds some regions to flush to reduce write buffer usage.\nSchedules background flush requests.\nWatch channel sender to notify workers to handle stalled …\nWatch channel sender to notify workers to handle stalled …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns region of specific <code>region_id</code>.\nReturns region of specific <code>region_id</code>.\nHandle to the worker thread.\nHandling alter related requests.\nHandles region metadata changes.\nHandles requests that changes region options, like TTL. It …\nHandles region background request\nHandles bulk insert requests.\nHandling catchup request.\nHandling close request.\nWhen compaction fails, we simply log the error.\nHandles compaction finished, update region version and …\nHandles compaction request submitted to region worker.\nHandling create request.\nTakes and handles all ddl requests.\nHandling drop request.\nHandling flush related requests.\nOn region flush job failed.\nOn region flush job finished.\nHandles manual flush request.\nHandles manifest.\nWrites region change action to the manifest and then …\nHandles region change result.\nWrites truncate action to the manifest and then applies it …\nHandling open request.\nHandle periodical tasks such as region auto flush.\nHandles region edit request.\nHandles region edit result.\nHandles a specific region’s stalled requests.\nHandles region sync request.\nDispatches and processes requests.\nHandles all stalled write requests.\nHandling truncate related requests.\nHandles truncate result.\nHandling write requests.\nTakes and handles all write requests.\nId of the worker.\nId of the worker.\nIntermediate manager for inverted index.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns true if the worker contains specific region.\nReturns true if the specific region exists.\nReturns true if the region is opening.\nReturns true if the specific region is opening.\nReturns true if the worker is still running.\nLast time to check regions periodically.\nEvent listener for tests.\nChecks whether the engine reaches flush threshold. If so, …\nMemtable builder provider for each region.\nCreates a flush task with specific <code>reason</code> for the <code>region</code>.\nNotifies the whole group that a flush job is finished so …\nManages object stores for manifest and SSTs.\nFlush is finished successfully.\nOn later drop task is finished.\nEngine is stalled.\nThe opening regions.\nRegions that are opening.\nValidates and groups requests by region.\nPuffin manager factory for index.\nBackground purge job scheduler.\nScheduler for file purgers.\nPushes a stalled request to the buffer.\nRequest receiver.\nGauge of regions in the worker.\nQueues for region edit requests.\nRegions bound to the worker.\nRegions bound to the worker.\nRejects a specific region’s stalled requests.\nRejects all stalled requests.\nRemoves stalled requests of specific region.\nReopens a region.\nStalled requests. Remember to use …\nStarts the worker loop.\nWhether to run the worker thread.\nWhether the worker thread is still running.\nSchedule compaction for the region if necessary.\nDatabase level metadata manager.\nRequest sender.\nRequest sender.\nHandles <code>set_region_role_gracefully</code>.\nSets whether the worker is still running.\nReturns true if the engine needs to reject some write …\nReturns the total number of all stalled requests.\nGauge of stalled request count.\nStalled write requests.\nStarts a region worker and its background thread.\nStarts a worker group.\nStop the worker.\nStops the worker group.\nSubmits request to background worker thread.\nSubmits a request to a worker in the group.\nProvider to get current time.\nUpdates the latest entry id since flush of the region. …\nWAL of the engine.\nGet worker for specific <code>region_id</code>.\nComputes a initial check delay for a worker.\nWorkers of the group.\nEngine write buffer manager.\nCreates a metadata after applying the alter <code>request</code> to the …\nConvert DfRecordBatch to gRPC rows.\nBackground GC task to remove the entire region path once …\nRemoves region dir if there is no parquet files, returns …\nA queue for temporary store region edit requests, if the …\nChecks the edit, writes and applies it.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nRejects delete request under append mode.\nSend rejected error to all <code>write_requests</code>.")