#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xbadffb04, "module_layout" },
	{ 0x7bd61166, "param_ops_uint" },
	{ 0x79edfb3e, "misc_deregister" },
	{ 0x9a5dc2b7, "misc_register" },
	{ 0x37a0cba, "kfree" },
	{ 0x316225ce, "__free_pages" },
	{ 0xc5850110, "printk" },
	{ 0x9f523720, "kmem_cache_alloc_trace" },
	{ 0x6879d5d9, "kmalloc_caches" },
	{ 0xc3dc6256, "remap_pfn_range" },
	{ 0x987c11c7, "__pv_phys_pfn_offset" },
	{ 0x5015cc7f, "mem_map" },
	{ 0xbef6bae2, "__alloc_pages_nodemask" },
	{ 0xb1ad28e0, "__gnu_mcount_nc" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "E7FD72BF50FD5B858A62C5F");
