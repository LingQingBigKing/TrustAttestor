#pragma once

class VectorImpl {
public:
    virtual                 ~VectorImpl() = default;

    /*! C-style array access */
    inline const void *arrayImpl() const { return mStorage; }

    /*! vector stats */
    inline size_t size() const { return mCount; }

    inline bool isEmpty() const { return mCount == 0; }

    inline const void *itemLocation(size_t index) const {
        const void *buffer = arrayImpl();
        if (buffer) {
            return reinterpret_cast<const char *>(buffer) + index * mItemSize;
        }
        return nullptr;
    }


    // These 2 fields are exposed in the inlines below,
    // so they're set in stone.
    void *mStorage;   // base address of the vector
    size_t mCount;     // number of items

    const uint32_t mFlags;
    const size_t mItemSize;
};


class AndroidRuntime {
public:
    virtual ~AndroidRuntime();

    inline VectorImpl *options() {
        return &mOptions;
    }

private:
    VectorImpl mOptions;
};
