#include "stdafx.h"

#include <array>
#include <mutex>
#include "Emu/IdManager.h"
#include "Emu/Cell/ErrorCodes.h"

#include "sys_crypto_engine.h"

#ifdef _WIN32
#include <Windows.h>
#include <bcrypt.h>
#endif

LOG_CHANNEL(sys_crypto_engine);

lv2_crypto_engine::lv2_crypto_engine(utils::serial& ar) noexcept
	: lv2_obj{1}
	, init(ar)
{
	if (init)
	{
	}
}

void lv2_crypto_engine::save(utils::serial& ar)
{
	USING_SERIALIZATION_VERSION(LLE);

	ar(init);

	if (init)
	{
	}
}

error_code sys_crypto_engine_create(vm::ptr<u32> id)
{
	sys_crypto_engine.notice("sys_crypto_engine_create(id=*0x%x)", id);

	if (!vm::check_addr(id.addr(), vm::page_writable, sizeof(u32)))
	{
		return CELL_EFAULT;
	}

	*id = idm::make<lv2_obj, lv2_crypto_engine>();

	return CELL_OK;
}

error_code sys_crypto_engine_destroy(u32 id)
{
	sys_crypto_engine.trace("sys_crypto_engine_destroy(id=0x%x)", id);

	auto ce = idm::get<lv2_obj, lv2_crypto_engine>(id, [&](lv2_crypto_engine &obj) -> bool {
		return obj.mutex.try_lock();
	});

	if (!ce)
	{
		return CELL_ESRCH;
	}

	if (!ce.ret)
	{
		return CELL_EBUSY;
	}

	idm::remove<lv2_obj, lv2_crypto_engine>(id);
	ce->mutex.unlock();

	return CELL_OK;
}

error_code sys_crypto_engine_random_generate(vm::ptr<void> buffer, u64 buffer_size)
{
	sys_crypto_engine.notice("sys_crypto_engine_random_generate(buffer=*0x%x, buffer_size=0x%x", buffer, buffer_size);

	if (buffer_size < 16) {
		return CELL_EINVAL;
	}

	std::array<u8, 16> temp{};

#ifdef _WIN32
	if (auto ret = BCryptGenRandom(nullptr, temp.data(), static_cast<ULONG>(temp.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG))
	{
		fmt::throw_exception("sys_crypto_engine_random_generate(): BCryptGenRandom failed (0x%08x)", ret);
	}
#else
	fs::file rnd{"/dev/urandom"};

	if (!rnd || rnd.read(temp.data(), temp.size()) != temp.size())
	{
		fmt::throw_exception("sys_crypto_engine_random_generate(): Failed to generate pseudo-random numbers");
	}
#endif

	if (!vm::check_addr(buffer.addr(), vm::page_writable, u32{temp.size()}))
	{
		return CELL_EFAULT;
	}

	std::memcpy(buffer.get_ptr(), temp.data(), temp.size());

	return CELL_OK;
}
