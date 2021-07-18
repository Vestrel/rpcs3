#include "stdafx.h"
#include "Emu/Memory/vm.h"
#include "Emu/IdManager.h"
#include "Emu/System.h"

#include "sys_process.h"
#include "sys_rsxaudio.h"

LOG_CHANNEL(sys_rsxaudio);
// TODO: check double calls
error_code sys_rsxaudio_initialize(vm::ptr<u32> handle)
{
	sys_rsxaudio.warning("sys_rsxaudio_initialize(handle=*0x%x)", handle);

	// Disallow multiple rsxaudio contexts
	if (idm::select<lv2_obj, lv2_rsxaudio>([&](u32 id, lv2_rsxaudio& obj) { return true; }))
		return CELL_EINVAL;

	if (!handle) return CELL_EFAULT;

	if (const u32 id = idm::make<lv2_obj, lv2_rsxaudio>())
	{
		auto rsxaudio_obj = idm::get<lv2_obj, lv2_rsxaudio>(id);
		std::lock_guard lock(rsxaudio_obj->mutex);

		rsxaudio_obj->shmem = vm::addr_t{vm::alloc(sizeof(sys_rsxaudio_shmem_t), vm::main)};
		rsxaudio_obj->dma_io_base = rsxaudio_obj->shmem; // TODO: verify

		if (!rsxaudio_obj->shmem)
		{
			idm::remove<lv2_obj, lv2_rsxaudio>(id);
			return CELL_ENOMEM;
		}

		sys_rsxaudio_shmem_t *sh_page = static_cast<sys_rsxaudio_shmem_t *>(vm::base(rsxaudio_obj->shmem));

		memset(&sh_page->ctrl, 0, sizeof(sh_page->ctrl));

		for (auto& uf : sh_page->ctrl.channel_uf)
		{
			uf.uf_event_cnt = 0;
			uf.unk1			= 0;
		}

		sh_page->ctrl.unk4 						= 0x8000;
		sh_page->ctrl.intr_thread_prio 			= 0xDEADBEEF;
		sh_page->ctrl.unk5 						= 0;

		rsxaudio_obj->init = true;
		*handle = id;

		return CELL_OK;
	}

	return CELL_ENOMEM;
}

error_code sys_rsxaudio_finalize(u32 handle)
{
	sys_rsxaudio.todo("sys_rsxaudio_finalize(handle=0x%x)", handle);

	const auto rsxaudio_obj = idm::withdraw<lv2_obj, lv2_rsxaudio>(handle);

	if (!rsxaudio_obj) return CELL_ESRCH;

	std::lock_guard lock(rsxaudio_obj->mutex); // TODO: destroy ports?

	if (!rsxaudio_obj->init) return CELL_ESRCH;

	rsxaudio_obj->init = false;
	vm::dealloc(rsxaudio_obj->shmem, vm::main);

	return CELL_OK;
}

error_code sys_rsxaudio_import_shared_memory(u32 handle, vm::ptr<u64> addr)
{
	sys_rsxaudio.warning("sys_rsxaudio_import_shared_memory(handle=0x%x, addr=*0x%x)", handle, addr);

	const auto rsxaudio_obj = idm::get<lv2_obj, lv2_rsxaudio>(handle);

	if (!rsxaudio_obj) return CELL_ESRCH;

	std::lock_guard<shared_mutex> lock(rsxaudio_obj->mutex);

	if (!rsxaudio_obj->init) return CELL_ESRCH;
	if (!addr) return CELL_EFAULT;

	*addr = rsxaudio_obj->shmem;

	return CELL_OK;
}

error_code sys_rsxaudio_unimport_shared_memory(u32 handle, vm::ptr<u64> addr)
{
	sys_rsxaudio.warning("sys_rsxaudio_unimport_shared_memory(handle=0x%x, addr=*0x%x)", handle, addr);

	// addr is not used
	// Should the page be protected?

	auto rsxaudio_obj = idm::get<lv2_obj, lv2_rsxaudio>(handle);
	if (!rsxaudio_obj || !rsxaudio_obj->init) return CELL_ESRCH;

	return CELL_OK;
}

error_code sys_rsxaudio_create_connection(u32 handle)
{
	sys_rsxaudio.warning("sys_rsxaudio_create_connection(handle=0x%x)", handle);

	const auto rsxaudio_obj = idm::get<lv2_obj, lv2_rsxaudio>(handle);

	if (!rsxaudio_obj) return CELL_ESRCH;

	std::lock_guard<shared_mutex> lock(rsxaudio_obj->mutex);

	if (!rsxaudio_obj->init) return CELL_ESRCH;

	sys_rsxaudio_shmem_t* sh_page = static_cast<sys_rsxaudio_shmem_t*>(vm::base(rsxaudio_obj->shmem));

	const error_code port_create_status = [&]() -> error_code {
		if (auto queue1 = idm::get<lv2_obj, lv2_event_queue>(sh_page->ctrl.event_queue_1_id))
		{
			if (auto queue2 = idm::get<lv2_obj, lv2_event_queue>(sh_page->ctrl.event_queue_2_id))
			{
				if (auto queue3 = idm::get<lv2_obj, lv2_event_queue>(sh_page->ctrl.event_queue_3_id))
				{
					if (auto port1 = idm::make<lv2_obj, lv2_event_port>(SYS_EVENT_PORT_LOCAL, 0))
					{
						if (auto port2 = idm::make<lv2_obj, lv2_event_port>(SYS_EVENT_PORT_LOCAL, 0))
						{
							if (auto port3 = idm::make<lv2_obj, lv2_event_port>(SYS_EVENT_PORT_LOCAL, 0))
							{
								rsxaudio_obj->event_queue[0] = queue1;
								rsxaudio_obj->event_queue[1] = queue2;
								rsxaudio_obj->event_queue[2] = queue3;

								rsxaudio_obj->event_port[0] = port1;
								rsxaudio_obj->event_port[1] = port2;
								rsxaudio_obj->event_port[2] = port3;

								return CELL_OK;
							}
							else
								idm::remove<lv2_obj, lv2_event_port>(port2);
						}
						else
							idm::remove<lv2_obj, lv2_event_port>(port1);
					}

					return CELL_ENOMEM;
				}
			}
		}

		return CELL_ESRCH;
	}();

	if (port_create_status != CELL_OK)
		return port_create_status;

	for (auto& rb : sh_page->ctrl.ringbuf)
	{
		rb.dma_init_addr = rsxaudio_obj->dma_io_base + offsetof(sys_rsxaudio_shmem_t, dma_init_region);
		rb.unk2          = 100;
	}

	for (u32 entry_idx = 0; entry_idx < SYS_RSXAUDIO_RINGBUF_SZ; entry_idx++)
	{
		sh_page->ctrl.ringbuf[SYS_RSXAUDIO_DST_SERIAL].entries[entry_idx].dma_addr = rsxaudio_obj->dma_io_base + u32{offsetof(sys_rsxaudio_shmem_t, dma_3wire_region)} + 0x1000 * entry_idx;
		sh_page->ctrl.ringbuf[SYS_RSXAUDIO_DST_SPDIF0].entries[entry_idx].dma_addr = rsxaudio_obj->dma_io_base + u32{offsetof(sys_rsxaudio_shmem_t, dma_spdif0_region)} + 0x400 * entry_idx;
		sh_page->ctrl.ringbuf[SYS_RSXAUDIO_DST_SPDIF1].entries[entry_idx].dma_addr = rsxaudio_obj->dma_io_base + u32{offsetof(sys_rsxaudio_shmem_t, dma_spdif1_region)} + 0x400 * entry_idx;
	}

	return CELL_OK;
}

error_code sys_rsxaudio_close_connection(u32 handle)
{
	sys_rsxaudio.warning("sys_rsxaudio_close_connection(handle=0x%x)", handle);

	const auto rsxaudio_obj = idm::get<lv2_obj, lv2_rsxaudio>(handle);

	if (!rsxaudio_obj) return CELL_ESRCH;

	std::lock_guard<shared_mutex> lock(rsxaudio_obj->mutex);

	if (!rsxaudio_obj->init) return CELL_ESRCH;

	auto &rsxaudio_thread = g_fxo->get<rsx_audio>();

	if (g_fxo->is_init<rsx_audio>())
		rsxaudio_thread.thread_prepared = false;

	for (u32 q_idx = 0; q_idx < SYS_RSXAUDIO_STREAM_CNT; q_idx++)
	{
		idm::remove<lv2_obj, lv2_event_port>(rsxaudio_obj->event_port[q_idx]);
		rsxaudio_obj->event_port[q_idx] = 0;
		rsxaudio_obj->event_queue[q_idx].reset();
	}

	return CELL_OK;
}

error_code sys_rsxaudio_prepare_process(u32 handle)
{
	sys_rsxaudio.warning("sys_rsxaudio_prepare_process(handle=0x%x)", handle);

	const auto rsxaudio_obj = idm::get<lv2_obj, lv2_rsxaudio>(handle);

	if (!rsxaudio_obj) return CELL_ESRCH;

	std::lock_guard<shared_mutex> lock(rsxaudio_obj->mutex);

	if (!rsxaudio_obj->init) return CELL_ESRCH;

	auto& rsxaudio_thread = g_fxo->is_init<rsx_audio>() ? g_fxo->get<rsx_audio>() : *g_fxo->init<rsx_audio>();

	if (!rsxaudio_thread.thread_prepared.compare_and_swap_test(0, 1))
		return -1; // TODO: verify

	return CELL_OK;
}

error_code sys_rsxaudio_start_process(u32 handle)
{
	sys_rsxaudio.warning("sys_rsxaudio_start_process(handle=0x%x)", handle);

	const auto rsxaudio_obj = idm::get<lv2_obj, lv2_rsxaudio>(handle);

	if (!rsxaudio_obj) return CELL_ESRCH;

	std::lock_guard<shared_mutex> lock(rsxaudio_obj->mutex);

	if (!rsxaudio_obj->init) return CELL_ESRCH;

	sys_rsxaudio_shmem_t* sh_page = static_cast<sys_rsxaudio_shmem_t*>(vm::base(rsxaudio_obj->shmem));

	for (auto& rb : sh_page->ctrl.ringbuf)
		if (rb.active) rsxaudio_obj->ringbuf_reader_clean_buf(&rb);

	for (auto& uf : sh_page->ctrl.channel_uf)
	{
		uf.uf_event_cnt = 0;
		uf.unk1			= 0;
	}

	auto& rsxaudio_thread = g_fxo->is_init<rsx_audio>() ? g_fxo->get<rsx_audio>() : *g_fxo->init<rsx_audio>();
	rsxaudio_thread.update_hw_param([&](auto& param) -> bool
	{
		if (sh_page->ctrl.ringbuf[SYS_RSXAUDIO_DST_SERIAL].active)
			param.serial.dma_en = true;

		if (sh_page->ctrl.ringbuf[SYS_RSXAUDIO_DST_SPDIF0].active)
			param.spdif[0].dma_en = true;

		if (sh_page->ctrl.ringbuf[SYS_RSXAUDIO_DST_SPDIF1].active)
			param.spdif[1].dma_en = true;

		return false;
	});

	rsxaudio_thread.rsxaudio_obj_ptr.store(rsxaudio_obj);

	// TODO: enqueue (2x) data blk from silence region

	for (u32 q_idx = 0; q_idx < SYS_RSXAUDIO_STREAM_CNT; q_idx++)
	{
		if (sh_page->ctrl.ringbuf[q_idx].active && rsxaudio_obj->event_port[q_idx])
			if (auto queue = rsxaudio_obj->event_queue[q_idx].lock())
				queue->send(s64{process_getpid()} << 32 | u64{rsxaudio_obj->event_port[q_idx]}, q_idx, 0, 0);
	}

	return CELL_OK;
}

error_code sys_rsxaudio_stop_process(u32 handle)
{
	sys_rsxaudio.warning("sys_rsxaudio_stop_process(handle=0x%x)", handle);

	const auto rsxaudio_obj = idm::get<lv2_obj, lv2_rsxaudio>(handle);

	if (!rsxaudio_obj) return CELL_ESRCH;

	std::lock_guard<shared_mutex> lock(rsxaudio_obj->mutex);

	if (!rsxaudio_obj->init) return CELL_ESRCH;

	auto &rsxaudio_thread = g_fxo->is_init<rsx_audio>() ? g_fxo->get<rsx_audio>() : *g_fxo->init<rsx_audio>();

	rsxaudio_thread.update_hw_param([&](rsxaudio_thread::hw_param_t &param) -> bool
	{
		param.serial.dma_en 	= false;
		param.serial.muted   	= true;
		memset(param.serial.en, 0, sizeof(param.serial.en));

		param.spdif[0].dma_en 	= false;
		if (!param.spdif[0].use_serial_buf)	param.spdif[0].en = false;

		param.spdif[1].dma_en 	= false;
		param.spdif[1].muted   	= true;
		if (!param.spdif[1].use_serial_buf)	param.spdif[1].en = false;

		return false;
	});

	sys_rsxaudio_shmem_t* sh_page = static_cast<sys_rsxaudio_shmem_t*>(vm::base(rsxaudio_obj->shmem));

	for (auto& rb : sh_page->ctrl.ringbuf)
		if (rb.active) rsxaudio_obj->ringbuf_reader_clean_buf(&rb);

	return CELL_OK;
}

error_code sys_rsxaudio_get_dma_param(u32 handle, u32 flag, vm::ptr<u64> out)
{
	sys_rsxaudio.trace("sys_rsxaudio_get_dma_param(handle=0x%x, flag=0x%x, out=0x%x)", handle, flag, out);

	const auto rsxaudio_obj = idm::get<lv2_obj, lv2_rsxaudio>(handle);

	if (!rsxaudio_obj) return CELL_ESRCH;

	std::lock_guard lock(rsxaudio_obj->mutex);

	if (!rsxaudio_obj->init) return CELL_ESRCH;
	if (!out) return CELL_EFAULT;

	if (flag == 1)
		*out = rsxaudio_obj->dma_io_id;
	else if (flag == 0)
		*out = rsxaudio_obj->dma_io_base;

	return CELL_OK;
}

rsxaudio_thread::rsxaudio_thread()
{
	auto hwp = std::make_shared<hw_param_t>();
	hwp->serial.muted = true;
	hwp->spdif[0].muted = true;
	hwp->spdif[0].use_serial_buf = true;
	hwp->spdif[1].muted = true;
	hwp->spdif[1].use_serial_buf = true;
	hw_param = hwp;
	hw_param_storage.push_back(hwp);
	timer.set_freq(4 * 2 * 48000, 1024);

	backend_init();
}

void rsxaudio_thread::operator()()
{
	thread_ctrl::scoped_priority high_prio(+1);

	while (thread_ctrl::state() != thread_state::aborting)
	{
		const auto wait_res = timer.wait(5, std::bind(&rsxaudio_thread::extract_audio_data, this, std::placeholders::_1));
		if (wait_res != audio_periodic_tmr::wait_result::SUCCESS && wait_res != audio_periodic_tmr::wait_result::TIMEOUT)
		{
			// Wait if timer is not running
			thread_ctrl::wait_for(1000);
		}
	}
}

rsxaudio_thread &rsxaudio_thread::operator=(thread_state)
{
	timer.stop();
	return *this;
}

bool rsxaudio_thread::extract_audio_data(bool underflow)
{
	auto rsxaudio_obj = rsxaudio_obj_ptr.load();

	if (!rsxaudio_obj || !thread_prepared)
	{
		return true; // TODO: enqueue silence
	}

	std::lock_guard<shared_mutex> rsxaudio_lock(rsxaudio_obj->mutex);

	if (!rsxaudio_obj->init)
	{
		return true; // TODO: enqueue silence
	}

	sys_rsxaudio_shmem_t* sh_page 	= static_cast<sys_rsxaudio_shmem_t*>(vm::base(rsxaudio_obj->shmem));
	const auto hw_cfg             	= hw_param.load();
	bool reset_periods 				= false;

	auto process_rb = [&](u8 rb_idx)
	{
		u64 a1, ts;
		rsxaudio_obj->ringbuf_reader_set_timestamp(&sh_page->ctrl.ringbuf[rb_idx]);

		if (enqueue_data(rb_idx, *hw_cfg, &sh_page->ctrl.ringbuf[rb_idx], *rsxaudio_obj) &&
		    rsxaudio_obj->ringbuf_reader_update_status(&sh_page->ctrl.ringbuf[rb_idx], &a1, &ts))
		{
			if (underflow)
			{
				sh_page->ctrl.channel_uf[rb_idx].uf_event_cnt++;
				reset_periods = true;
			}

			if (auto queue = rsxaudio_obj->event_queue[rb_idx].lock(); rsxaudio_obj->event_port[rb_idx])
				queue->send(s64{process_getpid()} << 32 | u64{rsxaudio_obj->event_port[rb_idx]}, rb_idx, a1, ts);
		}
	};

	if (hw_cfg->serial.dma_en && (hw_cfg->serial.en[0] | hw_cfg->serial.en[1] | hw_cfg->serial.en[2] | hw_cfg->serial.en[3]))
	{
		process_rb(SYS_RSXAUDIO_DST_SERIAL);
	}

	if (hw_cfg->spdif[0].dma_en && hw_cfg->spdif[0].en)
	{
		process_rb(SYS_RSXAUDIO_DST_SPDIF0);
	}

	if (hw_cfg->spdif[1].dma_en && hw_cfg->spdif[1].en)
	{
		process_rb(SYS_RSXAUDIO_DST_SPDIF1);
	}

	return reset_periods;
}

void rsxaudio_thread::update_hw_param(std::function<bool(hw_param_t&)> f)
{
	std::lock_guard lock(hw_upd_mutex);

	auto new_hw_param = std::make_shared<hw_param_t>();
	hw_param_storage.push_back(new_hw_param);
	memcpy(new_hw_param.operator->(), hw_param.load().operator->(), sizeof(hw_param_t));
	const bool upd_backend = f(*new_hw_param);
	hw_param.store(new_hw_param);

	if (upd_backend)
	{
		// TODO: update backend
		backend_flush();
		backend_play();
	}

	// Pool cleanup
	hw_param_storage.erase(
		std::remove_if(hw_param_storage.begin(), hw_param_storage.end(), [](auto& obj) { return obj.use_count() <= 1; }),
		hw_param_storage.end());
}

f32 rsxaudio_thread::pcm_32_to_float(s32 sample)
{
	return sample * (1.0f / 2147483648.0f);
}

f32 rsxaudio_thread::pcm_16_to_float(s16 sample)
{
	return sample * (1.0f / 32768.0f);
}

void rsxaudio_thread::pcm_3w_process_channel(u8 src_stream, u8 dst_stream, u8 ch_cnt, u8 swap, u8 word_bits, f32 *buf_out, const void *buf_in)
{
	const u32 input_word_sz = [&]()
	{
		switch (word_bits)
		{
			case SYS_RSXAUDIO_DATA_16BIT: return 2;
			case SYS_RSXAUDIO_DATA_20BIT:
			case SYS_RSXAUDIO_DATA_24BIT: return 4;
			default: ensure(false); return 0;
		}
	}();

	const u32 channel_offset = [&]()
	{
		switch (ch_cnt)
		{
			case SYS_RSXAUDIO_CH_2: return 1;
			case SYS_RSXAUDIO_CH_3:
			case SYS_RSXAUDIO_CH_4: return 2;
			case SYS_RSXAUDIO_CH_5:
			case SYS_RSXAUDIO_CH_6: return 3;
			case SYS_RSXAUDIO_CH_7:
			case SYS_RSXAUDIO_CH_8: return 4;
			default: ensure(false); return 0;
		}
	}();

	for (u64 location = 0; location < SYS_RSXAUDIO_3W_STREAM_CNT; location++)
	{
		for (u64 offset = 0; offset < SYS_RSXAUDIO_DATA_BLK_SIZE / 2; offset += input_word_sz)
		{
			u64 left_ch_dst = (location * SYS_RSXAUDIO_DATA_BLK_SIZE + offset * 2) / input_word_sz + dst_stream;
			u64 right_ch_dst = left_ch_dst;

			(swap == SYS_RSXAUDIO_NO_SWAP ? right_ch_dst : left_ch_dst) += channel_offset;

			const u64 left_ch_src = (location * SYS_RSXAUDIO_STREAM_SIZE + src_stream * SYS_RSXAUDIO_DATA_BLK_SIZE + offset) / input_word_sz;
			const u64 right_ch_src = left_ch_src + (SYS_RSXAUDIO_DATA_BLK_SIZE / 2) / input_word_sz;

			if (word_bits == SYS_RSXAUDIO_DATA_16BIT)
			{
				buf_out[left_ch_dst] = pcm_16_to_float(static_cast<const be_t<s16>*>(buf_in)[left_ch_src]);
				buf_out[right_ch_dst] = pcm_16_to_float(static_cast<const be_t<s16>*>(buf_in)[right_ch_src]);
			}
			else
			{
				// Looks like rsx accepts 32bit samples and downscales them by itself
				buf_out[left_ch_dst] = pcm_32_to_float(static_cast<const be_t<s32>*>(buf_in)[left_ch_src]);
				buf_out[right_ch_dst] = pcm_32_to_float(static_cast<const be_t<s32>*>(buf_in)[right_ch_src]);
			}
		}
	}
}

bool rsxaudio_thread::enqueue_data(u8 dst, hw_param_t& hwp, sys_rsxaudio_shmem_t::ringbuf_t *ring_buf, lv2_rsxaudio &rsxaudio_obj)
{
	const auto res = rsxaudio_obj.ringbuf_reader_get_addr(ring_buf);

	if (dst == SYS_RSXAUDIO_DST_SERIAL)
	{
		if (hwp.serial.muted) return res.first;

		if (hwp.serial.type == SYS_RSXAUDIO_TYPE_PCM)
		{
			// 16-bit PCM converted into float, so buffer must be twice as big
			static f32 buf[SYS_RSXAUDIO_STREAM_SIZE * SYS_RSXAUDIO_3W_STREAM_CNT / sizeof(s16)];

			const u32 channel_comp = [&]()
			{
				switch (hwp.serial.ch_cnt)
				{
					case SYS_RSXAUDIO_CH_2: return 1;
					case SYS_RSXAUDIO_CH_3:
					case SYS_RSXAUDIO_CH_4: return 2;
					case SYS_RSXAUDIO_CH_5:
					case SYS_RSXAUDIO_CH_6: return 3;
					case SYS_RSXAUDIO_CH_7:
					case SYS_RSXAUDIO_CH_8: return 4;
					default: ensure(false); return 0;
				}
			}();

			for (u8 ch_idx = 0; ch_idx < channel_comp; ch_idx++)
			{
				const u8 ch_mapped = hwp.serial.map[ch_idx];
				if (hwp.serial.en[ch_mapped])
					pcm_3w_process_channel(ch_mapped, ch_idx, hwp.serial.ch_cnt, hwp.serial.swap[ch_mapped], hwp.serial.depth, buf, vm::base(res.second));
			}

			u32 len = SYS_RSXAUDIO_STREAM_SIZE * channel_comp;
			if (hwp.serial.depth == SYS_RSXAUDIO_DATA_16BIT) len *= 2;

			dump_audio(buf, len);
		}
		else
		{
			fmt::throw_exception("RsxAudio (serial) - bitstream not implemented. Type: 0x%x", hwp.serial.type);
		}
	}
	else if (dst == SYS_RSXAUDIO_DST_SPDIF0)
	{
		if (hwp.spdif[0].muted) return res.first;

		fmt::throw_exception("RsxAudio (SPDIF0) - unimplemented");
	}
	else
	{
		if (hwp.spdif[1].muted) return res.first;

		fmt::throw_exception("RsxAudio (SPDIF1) - unimplemented");
	}

	return res.first;
}

void rsxaudio_thread::dump_audio(void *addr, u32 size)
{
	if (backend_buf_sz + size <= sizeof(backend_buf))
	{
		memcpy(&backend_buf[backend_buf_sz], addr, size);
		backend_buf_sz += size;
		return;
	}
	else
	{
		backend_enqueue(backend_buf, backend_buf_sz);
		backend_buf_sz = 0;
	}

	if (backend_buf_sz + size <= sizeof(backend_buf))
	{
		memcpy(&backend_buf[backend_buf_sz], addr, size);
		backend_buf_sz += size;
	}
}

void rsxaudio_thread::backend_init()
{
	auto new_backend = Emu.GetCallbacks().get_audio();

	if (new_backend->has_capability(AudioBackend::PLAY_PAUSE_FLUSH | AudioBackend::GET_NUM_ENQUEUED_SAMPLES))
	{
		backend.reset();
		backend = std::move(new_backend);

		backend->Open(10);
		backend->SetFrequencyRatio(1.0f);
	}
	else
	{
		sys_rsxaudio.error("Audio backend doesn't support required features");
	}
}

void rsxaudio_thread::backend_enqueue(const void *data, u32 sample_cnt)
{
	if (!backend)
		return;

	if (backend->AddData(data, sample_cnt))
	{
		// backend->Play();
	}
	else
	{
		// backend_flush();
	}
}

void rsxaudio_thread::backend_enqueue_silence(u64 blk_cnt)
{
	if (!backend)
		return;

	static constexpr u32 SILENCE_BLK[256] = {};

	for (u64 blk_idx = 0; blk_idx < blk_cnt; blk_idx++)
		backend->AddData(SILENCE_BLK, 256);

	backend->Play();
}

void rsxaudio_thread::backend_play()
{
	if (!backend)
		return;

	backend->Play();
	timer.start();
}

void rsxaudio_thread::backend_flush()
{
	if (!backend)
		return;

	timer.stop();
	backend->Pause();
	backend->Flush();
}
