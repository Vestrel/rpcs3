#pragma once

#include "sys_sync.h"
#include "Emu/Memory/vm_ptr.h"
#include "Emu/Cell/ErrorCodes.h"

struct lv2_crypto_engine final : public lv2_obj {
	static constexpr u32 id_base   = 0x78000000;

	shared_mutex mutex{};
	bool init = false;

	lv2_crypto_engine() noexcept = default;

	lv2_crypto_engine(utils::serial& ar) noexcept;	void save(utils::serial& ar);
};

// SysCalls

error_code sys_crypto_engine_create(vm::ptr<u32> id);
error_code sys_crypto_engine_destroy(u32 id);
error_code sys_crypto_engine_random_generate(vm::ptr<void> buffer, u64 buffer_size);
