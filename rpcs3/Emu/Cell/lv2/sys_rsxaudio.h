#pragma once

#include "sys_sync.h"
#include "sys_event.h"
#include "Utilities/Timer.h"
#include "Emu/Memory/vm_ptr.h"
#include "Emu/Cell/ErrorCodes.h"
#include "Emu/Audio/AudioDumper.h"
#include "Emu/Audio/AudioBackend.h"

#ifdef _WIN32
#include <windows.h>
#endif

enum : u32
{
	SYS_RSXAUDIO_STREAM_CNT 	= 3,
	SYS_RSXAUDIO_3W_STREAM_CNT  = 4,
	SYS_RSXAUDIO_STREAM_SIZE 	= 1024,
	SYS_RSXAUDIO_DATA_BLK_SIZE  = 256,

	SYS_RSXAUDIO_DATA_16BIT = 1,
	SYS_RSXAUDIO_DATA_20BIT = 2,
	SYS_RSXAUDIO_DATA_24BIT = 3,

	SYS_RSXAUDIO_FREQ_32K  = 1,
	SYS_RSXAUDIO_FREQ_44K  = 2,
	SYS_RSXAUDIO_FREQ_48K  = 3,
	SYS_RSXAUDIO_FREQ_88K  = 4,
	SYS_RSXAUDIO_FREQ_96K  = 5,
	SYS_RSXAUDIO_FREQ_176K = 6,
	SYS_RSXAUDIO_FREQ_192K = 7,

	SYS_RSXAUDIO_CH_2 = 0,
	SYS_RSXAUDIO_CH_3 = 1,
	SYS_RSXAUDIO_CH_4 = 2,
	SYS_RSXAUDIO_CH_5 = 3,
	SYS_RSXAUDIO_CH_6 = 4,
	SYS_RSXAUDIO_CH_7 = 5,
	SYS_RSXAUDIO_CH_8 = 6,

	SYS_RSXAUDIO_TYPE_PCM = 1,

	SYS_RSXAUDIO_NO_SWAP = 0,

	SYS_RSXAUDIO_SPDIF0 = 1,
	SYS_RSXAUDIO_SPDIF1 = 2,

	// Maps to ringbuffer index
	SYS_RSXAUDIO_DST_SERIAL = 0,
	SYS_RSXAUDIO_DST_SPDIF0 = 1,
	SYS_RSXAUDIO_DST_SPDIF1 = 2,

	SYS_RSXAUDIO_SRC_SERIAL = 0,
	SYS_RSXAUDIO_SRC_SPDIF 	= 1,

	SYS_RSXAUDIO_RINGBUF_SZ	= 16,
};

struct sys_rsxaudio_shmem_t
{
	struct ringbuf_t
	{
		struct entry_t
		{
			be_t<u32> valid;
			be_t<u32> unk1;
			be_t<u64> unk2;
			be_t<u64> timestamp;
			be_t<u32> unk3;
			be_t<u32> dma_addr;
		};

		be_t<u32> active;
		be_t<u32> unk2;
		be_t<s32> read_idx;
		be_t<u32> unk3;
		be_t<s32> read_max_idx;
		be_t<u32> unk4;
		be_t<s32> unk5;
		be_t<u32> unk6;
		be_t<u32> dma_init_addr;
		be_t<u32> unk7;
		be_t<u64> unk8;

		entry_t entries[16];
	};

	struct uf_event_t
	{
		be_t<u64> unk1;
		be_t<u32> uf_event_cnt;
		u8 unk2[244];
	};

	struct ctrl_t
	{
		ringbuf_t ringbuf[SYS_RSXAUDIO_STREAM_CNT];

		be_t<u32> unk1;
		be_t<u32> event_queue_1_id;
		u8 unk2[16];
		be_t<u32> event_queue_2_id;
		be_t<u32> spdif_ch0_channel_data_lo;
		be_t<u32> spdif_ch0_channel_data_hi;
		be_t<u32> spdif_ch0_channel_data_tx_cycles;
		be_t<u32> unk3;
		be_t<u32> event_queue_3_id;
		be_t<u32> spdif_ch1_channel_data_lo;
		be_t<u32> spdif_ch1_channel_data_hi;
		be_t<u32> spdif_ch1_channel_data_tx_cycles;
		be_t<u32> unk4;
		be_t<u32> intr_thread_prio;
		be_t<u32> unk5;
		u8 unk6[248];
		uf_event_t channel_uf[SYS_RSXAUDIO_STREAM_CNT];
		u8 pad[0x3530];
	};

	u8 dma_3wire_region[0x10000];
	u8 dma_spdif0_region[0x4000];
	u8 dma_spdif1_region[0x4000];
	u8 dma_init_region[0x4000];
	ctrl_t ctrl;
};

static_assert(sizeof(sys_rsxaudio_shmem_t::ringbuf_t) == 0x230U, "rsxAudioRingBufSizeTest");
static_assert(sizeof(sys_rsxaudio_shmem_t::uf_event_t) == 0x100U, "rsxAudioUfEventTest");
static_assert(sizeof(sys_rsxaudio_shmem_t::ctrl_t) == 0x4000U, "rsxAudioCtrlSizeTest");
static_assert(sizeof(sys_rsxaudio_shmem_t) == 0x20000U, "rsxAudioShmemSizeTest");

struct lv2_rsxaudio final : lv2_obj
{
	static const u32 id_base   = 0x60000000;
	static const u64 dma_io_id = 1;

	shared_mutex mutex{};
	atomic_t<bool> init = false;

	vm::addr_t shmem{};
	vm::addr_t dma_io_base{};

	std::weak_ptr<lv2_event_queue> event_queue[SYS_RSXAUDIO_STREAM_CNT]{};
	u32 event_port[SYS_RSXAUDIO_STREAM_CNT]{};

	lv2_rsxaudio()
	{
	}

	void ringbuf_reader_clean_buf(sys_rsxaudio_shmem_t::ringbuf_t* ring_buf)
	{
		if (ring_buf->active)
		{
			ring_buf->unk2     = 100;
			ring_buf->read_idx = 0;
			ring_buf->unk3     = 0;
			ring_buf->unk4     = 0;
			ring_buf->unk8     = 0;

			for (auto& ring_entry : ring_buf->entries)
			{
				ring_entry.valid     = 0;
				ring_entry.unk2      = 0;
				ring_entry.timestamp = 0;
			}
		}
	}

	void ringbuf_reader_set_timestamp(sys_rsxaudio_shmem_t::ringbuf_t* ring_buf)
	{
		s32 read_idx = ring_buf->read_max_idx - 1 + ring_buf->read_idx;

		if (ring_buf->read_max_idx > 2)
		{
			read_idx -= 1;
		}

		const auto entry_idx = read_idx % ring_buf->read_max_idx;
		ensure(entry_idx < SYS_RSXAUDIO_RINGBUF_SZ);

		ring_buf->entries[entry_idx].timestamp = get_timebased_time();
	}

	u32 ringbuf_reader_update_status(sys_rsxaudio_shmem_t::ringbuf_t* ring_buf, u64* unk, u64* timestamp)
	{
		ensure(ring_buf->read_idx < SYS_RSXAUDIO_RINGBUF_SZ);

		if ((ring_buf->entries[ring_buf->read_idx].valid & 1) == 0)
		{
			*timestamp = 0;
			*unk       = 0;

			return 0;
		}

		ring_buf->entries[ring_buf->read_idx].valid = 0;
		s32 read_idx                                = ring_buf->read_max_idx + ring_buf->read_idx;
		s32 cond                                    = 0;

		if (ring_buf->read_max_idx > 2)
		{
			read_idx -= 1;
			cond = 1;
		}

		ring_buf->unk4     = (ring_buf->unk4 + 1) % ring_buf->unk5;
		ring_buf->read_idx = (ring_buf->read_idx + 1) % ring_buf->read_max_idx;

		const auto entry_idx = read_idx % ring_buf->read_max_idx;
		ensure(entry_idx < SYS_RSXAUDIO_RINGBUF_SZ);

		*unk       = ring_buf->entries[entry_idx].unk2;
		*timestamp = ring_buf->entries[entry_idx].timestamp;

		return ring_buf->unk4 < 0x8000'0000 ? (ring_buf->unk4 % 32 - cond == 0) : 1;
	}

	std::pair<bool, u32> ringbuf_reader_get_addr(sys_rsxaudio_shmem_t::ringbuf_t* ring_buf)
	{
		std::pair<bool, u32> res;

		ensure(ring_buf->read_idx < SYS_RSXAUDIO_RINGBUF_SZ);

		if (ring_buf->entries[ring_buf->read_idx].valid & 1)
			res = std::make_pair(true, ring_buf->entries[ring_buf->read_idx].dma_addr);
		else
			res = std::make_pair(false, ring_buf->dma_init_addr);

		ensure(res.second < dma_io_base + sizeof(sys_rsxaudio_shmem_t) && res.second >= dma_io_base);

		res.second += shmem - dma_io_base;

		return res;
	}

	u64 get_spdif_channel_data(u8 spdif_idx, sys_rsxaudio_shmem_t* shmem)
	{
		if (spdif_idx == SYS_RSXAUDIO_SPDIF0)
		{
			if (shmem->ctrl.spdif_ch0_channel_data_tx_cycles)
			{
				shmem->ctrl.spdif_ch0_channel_data_tx_cycles--;
				return static_cast<u64>(shmem->ctrl.spdif_ch0_channel_data_hi) << 32 | shmem->ctrl.spdif_ch0_channel_data_lo;
			}
		}
		else
		{
			if (shmem->ctrl.spdif_ch1_channel_data_tx_cycles)
			{
				shmem->ctrl.spdif_ch1_channel_data_tx_cycles--;
				return static_cast<u64>(shmem->ctrl.spdif_ch1_channel_data_hi) << 32 | shmem->ctrl.spdif_ch1_channel_data_lo;
			}
		}
	}
};

class audio_periodic_tmr
{
private:

	static constexpr u32 MAX_BURST_PERIODS = SYS_RSXAUDIO_RINGBUF_SZ;

    u64 freq = 0;
	u64 blk_size = 0;
	u64 blk_cnt = 0;
    u64 start_time = 0;
	shared_mutex mutex{};
    bool running = false;
	bool in_wait = false;
	bool wait_cancel = false;

#ifdef _WIN32
    HANDLE timer_handle{};
#elif
#endif

	void sched_timer(u64 interval)
	{
#ifdef _WIN32
        LARGE_INTEGER due_time;
        due_time.QuadPart = -static_cast<s64>(interval * 10);
        SetWaitableTimerEx(timer_handle, &due_time, 0, nullptr, nullptr, nullptr, 0);
#elif
#endif
	}

	u64 get_rel_next_time(bool skip_periods)
	{
		blk_cnt++;
		const u64 blk_time = blk_size * 1'000'000 / freq;
		const u64 next_blk_time = start_time + blk_cnt * blk_time;
		const u64 max_time = start_time + blk_time * (blk_cnt + MAX_BURST_PERIODS - 1);
		const u64 crnt_time = get_system_time();

		if (skip_periods && crnt_time >= next_blk_time)
		{
			blk_cnt += 1 + (crnt_time - next_blk_time) / blk_time;
		}
		else if (crnt_time >= max_time)
		{
			blk_cnt += 1 + (crnt_time - max_time) / blk_time;
		}

		const u64 tgt_time = start_time + blk_cnt * blk_time;
		return crnt_time >= tgt_time ? 0ULL : tgt_time - crnt_time;
	}

	bool start_unlocked()
    {
		if (!blk_size || !freq)
		{
			return false;
		}

        stop_unlocked();
        start_time = get_system_time();
		running = true;
		sched_timer(get_rel_next_time(false));

		return true;
    }

    void stop_unlocked()
    {
        if (!running)
        {
            return;
        }

		running = false;
		blk_cnt = 0;

		if (in_wait)
		{
			sched_timer(0);
			wait_cancel = true;
		}
    }

public:

	enum wait_result
	{
		SUCCESS,
		INVALID_PARAM,
		TIMEOUT,
		TIMER_ERROR,
		TIMER_INACTIVE,
	};

	audio_periodic_tmr()
	{
#ifdef _WIN32
        timer_handle = CreateWaitableTimer(nullptr, true, nullptr);
        if (!timer_handle)
        {
            fmt::throw_exception("Failed to create waitable timer");
        }
#elif
#endif
	}

    ~audio_periodic_tmr()
    {
		std::lock_guard lock(mutex);
        stop_unlocked();

#ifdef _WIN32
        CloseHandle(timer_handle);
#elif
#endif
    }

	// Start or restart the timer
	bool start()
	{
		std::lock_guard lock(mutex);
		return start_unlocked();
	}

	// Stop the timer and cancel wait()
	void stop()
	{
		std::lock_guard lock(mutex);
		stop_unlocked();
	}

	// Wait with timeout until timer fires and call callback.
	// Callback parameter shows if running behind the schedule.
	// Callback result determines if periods would be skipped or not.
	wait_result wait(u64 timeout_ms, std::function<bool (bool)> callback)
    {
		std::unique_lock lock(mutex);

        if (!callback || in_wait)
        {
            return INVALID_PARAM;
        }

        if (!running)
        {
			return TIMER_INACTIVE;
		}

		in_wait = true;

		bool tmr_error = false;
		bool timeout   = false;

		lock.unlock();

#ifdef _WIN32
		const auto wait_status = WaitForSingleObject(timer_handle, timeout_ms);

		if (wait_status == WAIT_FAILED || wait_status == WAIT_ABANDONED)
		{
			tmr_error = true;
		}
		else if (wait_status == WAIT_TIMEOUT)
		{
			timeout = true;
		}
#elif
#endif
		lock.lock();

		wait_result res = TIMER_INACTIVE;

		if (tmr_error)
		{
			res = TIMER_ERROR;
		}
		else if (timeout)
		{
			res = TIMEOUT;
		}
		else if (running && !wait_cancel)
		{
			const u64 interval = [&]()
			{
				const auto res = get_rel_next_time(false);

				if (callback(!res) && !res)
				{
					return get_rel_next_time(true);
				}

				return res;
			}();

			sched_timer(interval);
			res = SUCCESS;
		}

		wait_cancel = false;
		in_wait     = false;

		return res;
	}

	bool set_freq(u64 freq, u64 blk_size)
    {
        if (freq && blk_size)
        {
			std::lock_guard lock(mutex);
            this->freq = freq;
			this->blk_size = blk_size;

			// Restart if running
			if (running)
			{
				start_unlocked();
			}

            return true;
        }

        return false;
    }
};

class rsxaudio_thread
{
public:
	struct serial_param_t
	{
		bool dma_en;
		bool muted;
		u8 freq;
		u8 depth;
		u8 ch_cnt;
		u8 type;
		u8 map[SYS_RSXAUDIO_3W_STREAM_CNT];
		u8 swap[SYS_RSXAUDIO_3W_STREAM_CNT];
		u8 en[SYS_RSXAUDIO_3W_STREAM_CNT];
	};

	struct spdif_param_t
	{
		bool en; 					// Only used if use_serial_buf == false
		bool dma_en;
		bool muted;
		bool use_serial_buf;
		u8 freq;
		u8 depth;
		u8 ch_cnt;
		u8 type;
	};

	struct hw_param_t
	{
		serial_param_t serial{};
		spdif_param_t spdif[2]{};
	};

	std::atomic<std::shared_ptr<lv2_rsxaudio>> rsxaudio_obj_ptr{};
	atomic_t<u32> thread_prepared = 0;

	void operator()();
	rsxaudio_thread &operator=(thread_state);

	bool extract_audio_data(bool underflow);

	rsxaudio_thread();

	void update_hw_param(std::function<bool(hw_param_t&)> f);

	static constexpr auto thread_name = "RsxAudio Thread"sv;

private:

	class audio_buffer
	{
	public:
		audio_buffer(u64 tgt_fill_ms, u64 buf_size);

		bool enque(const void *data, u64 size);
		u64 get_data(void *data, u64 size);

		void flush();
	};

	std::shared_ptr<AudioBackend> backend{}; // TODO: is this a problem?

	shared_mutex hw_upd_mutex{};
	std::atomic<std::shared_ptr<hw_param_t>> hw_param{};
	std::vector<std::shared_ptr<void>> hw_param_storage{};

	audio_periodic_tmr timer{};

	u32 backend_buf_sz = 0;
	u8 backend_buf[SYS_RSXAUDIO_STREAM_SIZE * 8]{};

	void backend_init();
	void backend_enqueue(const void *data, u32 sample_cnt);
	void backend_enqueue_silence(u64 blk_cnt);
	void backend_play();
	void backend_flush();

	f32 pcm_32_to_float(s32 sample);
	f32 pcm_16_to_float(s16 sample);
	void pcm_3w_process_channel(u8 src_stream, u8 dst_stream, u8 ch_cnt, u8 swap, u8 word_bits, f32* buf_out, const void* buf_in);
	bool enqueue_data(u8 dst, hw_param_t& hwp, sys_rsxaudio_shmem_t::ringbuf_t* ring_buf, lv2_rsxaudio &rsxaudio_obj);
	void dump_audio(void* addr, u32 size);
};

using rsx_audio = named_thread<rsxaudio_thread>;

// SysCalls

error_code sys_rsxaudio_initialize(vm::ptr<u32> handle);
error_code sys_rsxaudio_finalize(u32 handle);
error_code sys_rsxaudio_import_shared_memory(u32 handle, vm::ptr<u64> addr);
error_code sys_rsxaudio_unimport_shared_memory(u32 handle, vm::ptr<u64> addr);
error_code sys_rsxaudio_create_connection(u32 handle);
error_code sys_rsxaudio_close_connection(u32 handle);
error_code sys_rsxaudio_prepare_process(u32 handle);
error_code sys_rsxaudio_start_process(u32 handle);
error_code sys_rsxaudio_stop_process(u32 handle);
error_code sys_rsxaudio_get_dma_param(u32 handle, u32 flag, vm::ptr<u64> out);
