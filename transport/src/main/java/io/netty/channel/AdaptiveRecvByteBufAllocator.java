/*
 * Copyright 2012 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.channel;

import java.util.ArrayList;
import java.util.List;

import static io.netty.util.internal.ObjectUtil.checkPositive;
import static java.lang.Math.max;
import static java.lang.Math.min;

/**
 * The {@link RecvByteBufAllocator} that automatically increases and
 * decreases the predicted buffer size on feed back.
 * <p>
 * It gradually increases the expected number of readable bytes if the previous
 * read fully filled the allocated buffer.  It gradually decreases the expected
 * number of readable bytes if the read operation was not able to fill a certain
 * amount of the allocated buffer two times consecutively.  Otherwise, it keeps
 * returning the same prediction.
 */
// 基于历史的数据采集做预测:
//   1.前一次接收的数据完全读满了ByteBuf，则下次会增大缓冲区。
//   2.连续两次接收的数据小于指定值，则会缩小下次分配的缓冲区。
public class AdaptiveRecvByteBufAllocator extends DefaultMaxMessagesRecvByteBufAllocator {

    // 最小缓存（64），在SIZE_TABLE中对应的下标为3。
    static final int DEFAULT_MINIMUM = 64;
    // 初始化缓存大小，第一次分配缓存时，由于没有上一次实际收到的字节数做参考，需要给一个默认初始值
    static final int DEFAULT_INITIAL = 1024;
    // 最大缓存（65536），在SIZE_TABLE中对应的下标为38。
    static final int DEFAULT_MAXIMUM = 65536;

    // 上次预估缓存偏小，下次index的递增值。
    private static final int INDEX_INCREMENT = 4;
    // 上次预估缓存偏大，下次index的递减值。
    private static final int INDEX_DECREMENT = 1;
    // 按照从小到大顺序预先存储可以分配的缓存大小，
    // 从16开始，每次累加16，直到496，接着从512开始，每次增大一倍，直到溢出。
    private static final int[] SIZE_TABLE;

    static {
        List<Integer> sizeTable = new ArrayList<Integer>();
        // // 512字节内，以16字节为步长，递增
        for (int i = 16; i < 512; i += 16) {
            sizeTable.add(i);
        }

        // 512字节后，成倍扩容
        for (int i = 512; i > 0; i <<= 1) {
            sizeTable.add(i);
        }

        SIZE_TABLE = new int[sizeTable.size()];
        for (int i = 0; i < SIZE_TABLE.length; i ++) {
            SIZE_TABLE[i] = sizeTable.get(i);
        }
    }

    /**
     * @deprecated There is state for {@link #maxMessagesPerRead()} which is typically based upon channel type.
     */
    @Deprecated
    public static final AdaptiveRecvByteBufAllocator DEFAULT = new AdaptiveRecvByteBufAllocator();

    /**
     * 通过给定size查找下标，二分查找法。
     *     如果size不在SIZE_TABLE内，返回最接近它的一个稍小值的索引
     * @param size
     * @return
     */
    private static int getSizeTableIndex(final int size) {
        for (int low = 0, high = SIZE_TABLE.length - 1;;) {
            if (high < low) {
                return low;
            }
            if (high == low) {
                return high;
            }

            int mid = low + high >>> 1;
            int a = SIZE_TABLE[mid];
            int b = SIZE_TABLE[mid + 1];
            if (size > b) {
                low = mid + 1;
            } else if (size < a) {
                high = mid - 1;
            } else if (size == a) {
                return mid;
            } else {
                return mid + 1;
            }
        }
    }

    private final class HandleImpl extends MaxMessageHandle {
        private final int minIndex;
        private final int maxIndex;
        private int index;
        // // 下次接受的缓冲区大小
        private int nextReceiveBufferSize;
        private boolean decreaseNow;

        HandleImpl(int minIndex, int maxIndex, int initial) {
            this.minIndex = minIndex;
            this.maxIndex = maxIndex;

            // 根据初始值得到SIZE_TABLE的下标
            index = getSizeTableIndex(initial);
            // 第一次分配的缓冲区大小就是initial默认值
            nextReceiveBufferSize = SIZE_TABLE[index];
        }

        /**
         * bytes是上一次实际读取到的字节数。
         * @param bytes
         */
        @Override
        public void lastBytesRead(int bytes) {
            // If we read as much as we asked for we should check if we need to ramp up the size of our next guess.
            // This helps adjust more quickly when large amounts of data is pending and can avoid going back to
            // the selector to check for more data. Going back to the selector can add significant latency for large
            // data transfers.
            // 如果预期和实际相同
            if (bytes == attemptedBytesRead()) {
                // 实际读取的字节数填满了缓冲区，则扩容。
                record(bytes);
            }
            // 调用父类方法，将数值累加到 totalBytesRead
            super.lastBytesRead(bytes);
        }

        // 预测下次需要分配的缓冲区大小
        @Override
        public int guess() {
            return nextReceiveBufferSize;
        }

        // 读取完之后，记录下，计算出下一次应该分配的大小
        private void record(int actualReadBytes) {
            // 如果连续两次，读取的字节数 小于等于 前一个容量大小
            if (actualReadBytes <= SIZE_TABLE[max(0, index - INDEX_DECREMENT)]) {
                if (decreaseNow) {
                    index = max(index - INDEX_DECREMENT, minIndex);
                    nextReceiveBufferSize = SIZE_TABLE[index];
                    decreaseNow = false;
                } else {
                    decreaseNow = true;
                }
            } else if (actualReadBytes >= nextReceiveBufferSize) {
                index = min(index + INDEX_INCREMENT, maxIndex);
                nextReceiveBufferSize = SIZE_TABLE[index];
                decreaseNow = false;
            }
        }

        // 数据读取完毕，根据本次读取的总字节数，自适应调整下次应该分配的缓冲区大小
        @Override
        public void readComplete() {
            record(totalBytesRead());
        }
    }

    private final int minIndex;
    private final int maxIndex;
    private final int initial;

    /**
     * Creates a new predictor with the default parameters.  With the default
     * parameters, the expected buffer size starts from {@code 1024}, does not
     * go down below {@code 64}, and does not go up above {@code 65536}.
     */
    public AdaptiveRecvByteBufAllocator() {
        this(DEFAULT_MINIMUM, DEFAULT_INITIAL, DEFAULT_MAXIMUM);
    }

    /**
     * Creates a new predictor with the specified parameters.
     *
     * @param minimum  the inclusive lower bound of the expected buffer size
     * @param initial  the initial buffer size when no feed back was received
     * @param maximum  the inclusive upper bound of the expected buffer size
     */
    public AdaptiveRecvByteBufAllocator(int minimum, int initial, int maximum) {
        checkPositive(minimum, "minimum");
        if (initial < minimum) {
            throw new IllegalArgumentException("initial: " + initial);
        }
        if (maximum < initial) {
            throw new IllegalArgumentException("maximum: " + maximum);
        }

        int minIndex = getSizeTableIndex(minimum);
        if (SIZE_TABLE[minIndex] < minimum) {
            this.minIndex = minIndex + 1;
        } else {
            this.minIndex = minIndex;
        }

        int maxIndex = getSizeTableIndex(maximum);
        if (SIZE_TABLE[maxIndex] > maximum) {
            this.maxIndex = maxIndex - 1;
        } else {
            this.maxIndex = maxIndex;
        }

        this.initial = initial;
    }

    @SuppressWarnings("deprecation")
    @Override
    public Handle newHandle() {
        return new HandleImpl(minIndex, maxIndex, initial);
    }

    @Override
    public AdaptiveRecvByteBufAllocator respectMaybeMoreData(boolean respectMaybeMoreData) {
        super.respectMaybeMoreData(respectMaybeMoreData);
        return this;
    }
}
