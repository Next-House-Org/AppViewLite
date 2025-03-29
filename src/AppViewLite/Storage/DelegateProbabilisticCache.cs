using AppViewLite.Storage;
using System;

namespace AppViewLite.Storage
{
    public class DelegateProbabilisticCache<TKey, TValue, TProbabilisticKey> : CombinedPersistentMultiDictionary<TKey, TValue>.CachedView where TKey : unmanaged, IComparable<TKey> where TValue : unmanaged, IComparable<TValue>, IEquatable<TValue> where TProbabilisticKey : unmanaged
    {
        private readonly long sizeInBytes;
        private readonly int hashFunctions;
        private readonly ProbabilisticSet<TProbabilisticKey> probabilisticSet;
        private readonly string baseIdentifier;
        private readonly Func<TKey, TValue, TProbabilisticKey> getProbabilisticKey;
        public DelegateProbabilisticCache(string baseIdentifier, long sizeInBytes, int hashFunctions, Func<TKey, TValue, TProbabilisticKey> getProbabilisticKey)
        {
            this.baseIdentifier = baseIdentifier;
            this.sizeInBytes = sizeInBytes;
            this.hashFunctions = hashFunctions;
            this.getProbabilisticKey = getProbabilisticKey;
            this.probabilisticSet = new(sizeInBytes, hashFunctions);
        }

        public override string Identifier => baseIdentifier + "-" + probabilisticSet.BitsPerFunction + "-" + hashFunctions;

        public override bool CanBeUsedByReplica => true;

        public override void LoadCacheFile(CombinedPersistentMultiDictionary<TKey, TValue>.SliceInfo slice, string cachePath, int sliceIndex)
        {
            probabilisticSet.UnionWith(ProbabilisticSetIo.ReadCompressedProbabilisticSetFromFile(cachePath));
        }

        public override void LoadFromOriginalSlice(CombinedPersistentMultiDictionary<TKey, TValue>.SliceInfo slice)
        {
            ReadInto(slice, probabilisticSet);
        }

        public override void MaterializeCacheFile(CombinedPersistentMultiDictionary<TKey, TValue>.SliceInfo slice, string destination)
        {
            var cache = new ProbabilisticSet<TProbabilisticKey>(sizeInBytes, hashFunctions);
            ReadInto(slice, cache);
            ProbabilisticSetIo.WriteCompressedProbabilisticSetToFile(destination, cache);
        }

        private void ReadInto(CombinedPersistentMultiDictionary<TKey, TValue>.SliceInfo slice, ProbabilisticSet<TProbabilisticKey> cache)
        {
            foreach (var group in slice.Reader.Enumerate())
            {
                var target = group.Key;
                var valueSpan = group.Values.Span;
                for (long i = 0; i < valueSpan.Length; i++)
                {
                    cache.Add(getProbabilisticKey(target, valueSpan[i]));
                }
            }
        }

        public override bool ShouldPersistCacheForSlice(CombinedPersistentMultiDictionary<TKey, TValue>.SliceInfo slice)
        {
            var sliceSize = slice.SizeInBytes;
            var cacheSize = probabilisticSet.SizeInBytes;
            return sliceSize * 16 > cacheSize;
        }

        public bool PossiblyContains(TProbabilisticKey probabilisticKey)
        {
            return probabilisticSet.PossiblyContains(probabilisticKey);
        }

        public override void Add(TKey key, TValue value)
        {
            probabilisticSet.Add(getProbabilisticKey(key, value));
        }

        public override object? GetCounters()
        {
            return probabilisticSet.GetCounters();
        }
    }

}
