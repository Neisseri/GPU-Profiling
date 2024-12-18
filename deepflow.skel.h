/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __DEEPFLOW_BPF_SKEL_H__
#define __DEEPFLOW_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

#define BPF_SKEL_SUPPORTS_MAP_AUTO_ATTACH 1

struct deepflow_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *gpu_memory_info;
		struct bpf_map *cuda_malloc_hash;
		struct bpf_map *malloc_ptr_info;
		struct bpf_map *rodata_str1_1;
	} maps;
	struct {
		struct bpf_program *cuda_malloc;
		struct bpf_program *cuda_malloc_ret;
		struct bpf_program *cuda_free;
	} progs;
	struct {
		struct bpf_link *cuda_malloc;
		struct bpf_link *cuda_malloc_ret;
		struct bpf_link *cuda_free;
	} links;

#ifdef __cplusplus
	static inline struct deepflow_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct deepflow_bpf *open_and_load();
	static inline int load(struct deepflow_bpf *skel);
	static inline int attach(struct deepflow_bpf *skel);
	static inline void detach(struct deepflow_bpf *skel);
	static inline void destroy(struct deepflow_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
deepflow_bpf__destroy(struct deepflow_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
deepflow_bpf__create_skeleton(struct deepflow_bpf *obj);

static inline struct deepflow_bpf *
deepflow_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct deepflow_bpf *obj;
	int err;

	obj = (struct deepflow_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = deepflow_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	deepflow_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct deepflow_bpf *
deepflow_bpf__open(void)
{
	return deepflow_bpf__open_opts(NULL);
}

static inline int
deepflow_bpf__load(struct deepflow_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct deepflow_bpf *
deepflow_bpf__open_and_load(void)
{
	struct deepflow_bpf *obj;
	int err;

	obj = deepflow_bpf__open();
	if (!obj)
		return NULL;
	err = deepflow_bpf__load(obj);
	if (err) {
		deepflow_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
deepflow_bpf__attach(struct deepflow_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
deepflow_bpf__detach(struct deepflow_bpf *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *deepflow_bpf__elf_bytes(size_t *sz);

static inline int
deepflow_bpf__create_skeleton(struct deepflow_bpf *obj)
{
	struct bpf_object_skeleton *s;
	struct bpf_map_skeleton *map __attribute__((unused));
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "deepflow_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 4;
	s->map_skel_sz = 24;
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt,
			sizeof(*s->maps) > 24 ? sizeof(*s->maps) : 24);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	map = (struct bpf_map_skeleton *)((char *)s->maps + 0 * s->map_skel_sz);
	map->name = "gpu_memory_info";
	map->map = &obj->maps.gpu_memory_info;

	map = (struct bpf_map_skeleton *)((char *)s->maps + 1 * s->map_skel_sz);
	map->name = "cuda_malloc_hash";
	map->map = &obj->maps.cuda_malloc_hash;

	map = (struct bpf_map_skeleton *)((char *)s->maps + 2 * s->map_skel_sz);
	map->name = "malloc_ptr_info";
	map->map = &obj->maps.malloc_ptr_info;

	map = (struct bpf_map_skeleton *)((char *)s->maps + 3 * s->map_skel_sz);
	map->name = ".rodata.str1.1";
	map->map = &obj->maps.rodata_str1_1;

	/* programs */
	s->prog_cnt = 3;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "cuda_malloc";
	s->progs[0].prog = &obj->progs.cuda_malloc;
	s->progs[0].link = &obj->links.cuda_malloc;

	s->progs[1].name = "cuda_malloc_ret";
	s->progs[1].prog = &obj->progs.cuda_malloc_ret;
	s->progs[1].link = &obj->links.cuda_malloc_ret;

	s->progs[2].name = "cuda_free";
	s->progs[2].prog = &obj->progs.cuda_free;
	s->progs[2].link = &obj->links.cuda_free;

	s->data = deepflow_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *deepflow_bpf__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xb8\x1f\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x0e\0\
\x01\0\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x75\x70\
\x72\x6f\x62\x65\x2f\x2f\x6d\x6e\x74\x2f\x65\x2f\x50\x72\x6f\x67\x72\x61\x6d\
\x2f\x65\x62\x70\x66\x2d\x63\x75\x64\x61\x2d\x65\x78\x61\x6d\x70\x6c\x65\x73\
\x2f\x63\x75\x64\x61\x2f\x63\x70\x6d\x65\x6d\x3a\x63\x75\x64\x61\x4d\x61\x6c\
\x6c\x6f\x63\0\x75\x72\x65\x74\x70\x72\x6f\x62\x65\x2f\x2f\x6d\x6e\x74\x2f\x65\
\x2f\x50\x72\x6f\x67\x72\x61\x6d\x2f\x65\x62\x70\x66\x2d\x63\x75\x64\x61\x2d\
\x65\x78\x61\x6d\x70\x6c\x65\x73\x2f\x63\x75\x64\x61\x2f\x63\x70\x6d\x65\x6d\
\x3a\x63\x75\x64\x61\x4d\x61\x6c\x6c\x6f\x63\0\x75\x70\x72\x6f\x62\x65\x2f\x2f\
\x6d\x6e\x74\x2f\x65\x2f\x50\x72\x6f\x67\x72\x61\x6d\x2f\x65\x62\x70\x66\x2d\
\x63\x75\x64\x61\x2d\x65\x78\x61\x6d\x70\x6c\x65\x73\x2f\x63\x75\x64\x61\x2f\
\x63\x70\x6d\x65\x6d\x3a\x63\x75\x64\x61\x46\x72\x65\x65\0\x6c\x69\x63\x65\x6e\
\x73\x65\0\x2e\x6d\x61\x70\x73\0\x2e\x72\x6f\x64\x61\x74\x61\x2e\x73\x74\x72\
\x31\x2e\x31\0\x64\x65\x65\x70\x66\x6c\x6f\x77\x2e\x62\x70\x66\x2e\x63\0\x4c\
\x42\x42\x30\x5f\x32\0\x4c\x42\x42\x30\x5f\x33\0\x4c\x42\x42\x30\x5f\x35\0\x4c\
\x42\x42\x30\x5f\x36\0\x4c\x42\x42\x30\x5f\x38\0\x4c\x42\x42\x31\x5f\x35\0\x4c\
\x42\x42\x31\x5f\x34\0\x4c\x42\x42\x32\x5f\x32\0\x4c\x42\x42\x32\x5f\x34\0\x63\
\x75\x64\x61\x5f\x6d\x61\x6c\x6c\x6f\x63\0\x67\x70\x75\x5f\x6d\x65\x6d\x6f\x72\
\x79\x5f\x69\x6e\x66\x6f\0\x6d\x61\x6c\x6c\x6f\x63\x5f\x70\x74\x72\x5f\x69\x6e\
\x66\x6f\0\x63\x75\x64\x61\x5f\x6d\x61\x6c\x6c\x6f\x63\x5f\x72\x65\x74\0\x63\
\x75\x64\x61\x5f\x6d\x61\x6c\x6c\x6f\x63\x5f\x68\x61\x73\x68\0\x63\x75\x64\x61\
\x5f\x66\x72\x65\x65\0\x4c\x49\x43\x45\x4e\x53\x45\0\x2e\x72\x65\x6c\x75\x70\
\x72\x6f\x62\x65\x2f\x2f\x6d\x6e\x74\x2f\x65\x2f\x50\x72\x6f\x67\x72\x61\x6d\
\x2f\x65\x62\x70\x66\x2d\x63\x75\x64\x61\x2d\x65\x78\x61\x6d\x70\x6c\x65\x73\
\x2f\x63\x75\x64\x61\x2f\x63\x70\x6d\x65\x6d\x3a\x63\x75\x64\x61\x4d\x61\x6c\
\x6c\x6f\x63\0\x2e\x72\x65\x6c\x75\x72\x65\x74\x70\x72\x6f\x62\x65\x2f\x2f\x6d\
\x6e\x74\x2f\x65\x2f\x50\x72\x6f\x67\x72\x61\x6d\x2f\x65\x62\x70\x66\x2d\x63\
\x75\x64\x61\x2d\x65\x78\x61\x6d\x70\x6c\x65\x73\x2f\x63\x75\x64\x61\x2f\x63\
\x70\x6d\x65\x6d\x3a\x63\x75\x64\x61\x4d\x61\x6c\x6c\x6f\x63\0\x2e\x72\x65\x6c\
\x75\x70\x72\x6f\x62\x65\x2f\x2f\x6d\x6e\x74\x2f\x65\x2f\x50\x72\x6f\x67\x72\
\x61\x6d\x2f\x65\x62\x70\x66\x2d\x63\x75\x64\x61\x2d\x65\x78\x61\x6d\x70\x6c\
\x65\x73\x2f\x63\x75\x64\x61\x2f\x63\x70\x6d\x65\x6d\x3a\x63\x75\x64\x61\x46\
\x72\x65\x65\0\x2e\x42\x54\x46\0\x2e\x42\x54\x46\x2e\x65\x78\x74\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xec\0\0\0\x04\0\xf1\xff\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\xfb\0\0\0\0\0\x03\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02\x01\0\0\0\0\x03\0\
\xc8\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x09\x01\0\0\0\0\x03\0\x10\x01\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x10\x01\0\0\0\0\x03\0\x60\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x17\
\x01\0\0\0\0\x03\0\x78\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x04\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1e\x01\0\0\0\0\x04\0\x30\x02\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x25\x01\0\0\0\0\x04\0\xf0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\
\0\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x2c\x01\0\0\0\0\x05\0\x30\x01\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x33\x01\0\0\0\0\x05\0\x78\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x3a\x01\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\x88\x02\0\0\0\0\0\0\x46\x01\0\0\x11\0\
\x07\0\0\0\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x56\x01\0\0\x11\0\x07\0\x40\0\0\0\0\0\
\0\0\x20\0\0\0\0\0\0\0\x66\x01\0\0\x12\0\x04\0\0\0\0\0\0\0\0\0\x40\x02\0\0\0\0\
\0\0\x76\x01\0\0\x11\0\x07\0\x20\0\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x87\x01\0\0\
\x12\0\x05\0\0\0\0\0\0\0\0\0\x88\x01\0\0\0\0\0\0\x91\x01\0\0\x11\0\x06\0\0\0\0\
\0\0\0\0\0\x0d\0\0\0\0\0\0\0\x79\x18\x68\0\0\0\0\0\x79\x16\x70\0\0\0\0\0\x85\0\
\0\0\x0e\0\0\0\x77\0\0\0\x20\0\0\0\x63\x0a\xfc\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\
\x07\x02\0\0\xfc\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\
\0\0\0\xbf\x07\0\0\0\0\0\0\x15\x07\x04\0\0\0\0\0\x61\x71\0\0\0\0\0\0\x0f\x81\0\
\0\0\0\0\0\x63\x17\0\0\0\0\0\0\x05\0\x09\0\0\0\0\0\x63\x8a\xb8\xff\0\0\0\0\xbf\
\xa2\0\0\0\0\0\0\x07\x02\0\0\xfc\xff\xff\xff\xbf\xa3\0\0\0\0\0\0\x07\x03\0\0\
\xb8\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x04\0\0\0\0\0\0\x85\0\
\0\0\x02\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xfc\xff\xff\xff\x18\x01\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\x15\0\x03\0\0\0\0\0\x7b\x80\x08\0\0\0\
\0\0\x7b\x60\0\0\0\0\0\0\x05\0\x0a\0\0\0\0\0\x7b\x8a\xc0\xff\0\0\0\0\x7b\x6a\
\xb8\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xfc\xff\xff\xff\xbf\xa3\0\0\0\
\0\0\0\x07\x03\0\0\xb8\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x04\
\0\0\0\0\0\0\x85\0\0\0\x02\0\0\0\xb7\x04\0\0\0\0\0\0\x15\x07\x01\0\0\0\0\0\x61\
\x74\0\0\0\0\0\0\xb7\x01\0\0\x0a\0\0\0\x6b\x1a\xf8\xff\0\0\0\0\x18\x01\0\0\x72\
\x20\x3d\x20\0\0\0\0\x25\x6c\x6c\x75\x7b\x1a\xf0\xff\0\0\0\0\x18\x01\0\0\x36\
\x34\x29\x64\0\0\0\0\x65\x76\x50\x74\x7b\x1a\xe8\xff\0\0\0\0\x18\x01\0\0\x25\
\x75\x2c\x20\0\0\0\0\x28\x5f\x5f\x75\x7b\x1a\xe0\xff\0\0\0\0\x18\x01\0\0\x5f\
\x64\x61\x74\0\0\0\0\x61\x20\x3d\x20\x7b\x1a\xd8\xff\0\0\0\0\x18\x01\0\0\x20\
\x25\x75\x2c\0\0\0\0\x20\x6d\x65\x6d\x7b\x1a\xd0\xff\0\0\0\0\x18\x01\0\0\x64\
\x3a\x20\x70\0\0\0\0\x69\x64\x20\x3d\x7b\x1a\xc8\xff\0\0\0\0\x18\x01\0\0\x6f\
\x63\x20\x63\0\0\0\0\x61\x6c\x6c\x65\x7b\x1a\xc0\xff\0\0\0\0\x18\x01\0\0\x63\
\x75\x64\x61\0\0\0\0\x4d\x61\x6c\x6c\x7b\x1a\xb8\xff\0\0\0\0\x61\xa3\xfc\xff\0\
\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\xb8\xff\xff\xff\xb7\x02\0\0\x42\0\0\0\
\xbf\x65\0\0\0\0\0\0\x85\0\0\0\x06\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\
\x79\x16\x50\0\0\0\0\0\x85\0\0\0\x0e\0\0\0\x77\0\0\0\x20\0\0\0\x63\x0a\xfc\xff\
\0\0\0\0\x67\x06\0\0\x20\0\0\0\x77\x06\0\0\x20\0\0\0\x55\x06\x3f\0\0\0\0\0\xbf\
\xa2\0\0\0\0\0\0\x07\x02\0\0\xfc\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x85\0\0\0\x01\0\0\0\x15\0\x39\0\0\0\0\0\x79\x03\0\0\0\0\0\0\x79\x06\x08\0\0\
\0\0\0\x63\x6a\xf8\xff\0\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\xf0\xff\xff\xff\
\xb7\x02\0\0\x08\0\0\0\xbf\x07\0\0\0\0\0\0\x85\0\0\0\x70\0\0\0\x79\xa5\xf0\xff\
\0\0\0\0\x7b\x5a\xe8\xff\0\0\0\0\xb7\x01\0\0\0\0\0\0\x73\x1a\xe4\xff\0\0\0\0\
\xb7\x01\0\0\x6c\x6c\x75\x0a\x63\x1a\xe0\xff\0\0\0\0\x18\x01\0\0\x61\x64\x64\
\x72\0\0\0\0\x20\x3d\x20\x25\x7b\x1a\xd8\xff\0\0\0\0\x18\x01\0\0\x3d\x20\x25\
\x6c\0\0\0\0\x6c\x75\x2c\x20\x7b\x1a\xd0\xff\0\0\0\0\x18\x01\0\0\x29\x64\x65\
\x76\0\0\0\0\x50\x74\x72\x20\x7b\x1a\xc8\xff\0\0\0\0\x18\x01\0\0\x2c\x20\x28\
\x5f\0\0\0\0\x5f\x75\x36\x34\x7b\x1a\xc0\xff\0\0\0\0\x18\x01\0\0\x70\x69\x64\
\x20\0\0\0\0\x3d\x20\x25\x75\x7b\x1a\xb8\xff\0\0\0\0\x18\x01\0\0\x6f\x63\x20\
\x52\0\0\0\0\x65\x74\x3a\x20\x7b\x1a\xb0\xff\0\0\0\0\x18\x01\0\0\x63\x75\x64\
\x61\0\0\0\0\x4d\x61\x6c\x6c\x7b\x1a\xa8\xff\0\0\0\0\x79\x74\0\0\0\0\0\0\x61\
\xa3\xfc\xff\0\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\xa8\xff\xff\xff\xb7\x02\0\
\0\x3d\0\0\0\x85\0\0\0\x06\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xe8\xff\xff\
\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\x15\0\x02\0\0\0\0\
\0\x63\x60\0\0\0\0\0\0\x05\0\x08\0\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xe8\
\xff\xff\xff\xbf\xa3\0\0\0\0\0\0\x07\x03\0\0\xf8\xff\xff\xff\x18\x01\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\xb7\x04\0\0\0\0\0\0\x85\0\0\0\x02\0\0\0\xb7\0\0\0\0\0\0\0\
\x95\0\0\0\0\0\0\0\x79\x16\x70\0\0\0\0\0\x85\0\0\0\x0e\0\0\0\x77\0\0\0\x20\0\0\
\0\x63\x0a\xfc\xff\0\0\0\0\x7b\x6a\xf0\xff\0\0\0\0\x18\x01\0\0\x20\x3d\x20\x25\
\0\0\0\0\x6c\x6c\x75\x0a\x7b\x1a\xe0\xff\0\0\0\0\x18\x01\0\0\x34\x29\x64\x65\0\
\0\0\0\x76\x50\x74\x72\x7b\x1a\xd8\xff\0\0\0\0\x18\x01\0\0\x75\x2c\x20\x28\0\0\
\0\0\x5f\x5f\x75\x36\x7b\x1a\xd0\xff\0\0\0\0\x18\x01\0\0\x20\x70\x69\x64\0\0\0\
\0\x20\x3d\x20\x25\x7b\x1a\xc8\xff\0\0\0\0\x18\x01\0\0\x20\x63\x61\x6c\0\0\0\0\
\x6c\x65\x64\x3a\x7b\x1a\xc0\xff\0\0\0\0\x18\x01\0\0\x63\x75\x64\x61\0\0\0\0\
\x46\x72\x65\x65\x7b\x1a\xb8\xff\0\0\0\0\xb7\x07\0\0\0\0\0\0\x73\x7a\xe8\xff\0\
\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\xb8\xff\xff\xff\xb7\x02\0\0\x31\0\0\0\
\xbf\x03\0\0\0\0\0\0\xbf\x64\0\0\0\0\0\0\x85\0\0\0\x06\0\0\0\xbf\xa2\0\0\0\0\0\
\0\x07\x02\0\0\xf0\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\
\x01\0\0\0\x15\0\x01\0\0\0\0\0\x61\x07\0\0\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\
\0\0\xfc\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\
\x15\0\x03\0\0\0\0\0\x61\x01\0\0\0\0\0\0\x1f\x71\0\0\0\0\0\0\x63\x10\0\0\0\0\0\
\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x44\x75\x61\x6c\x20\x42\x53\x44\x2f\x47\
\x50\x4c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x63\x75\x64\x61\x4d\x61\
\x6c\x6c\x6f\x63\x20\x63\x61\x6c\x6c\x65\x64\x3a\x20\x70\x69\x64\x20\x3d\x20\
\x25\x75\x2c\x20\x6d\x65\x6d\x5f\x64\x61\x74\x61\x20\x3d\x20\x25\x75\x2c\x20\
\x28\x5f\x5f\x75\x36\x34\x29\x64\x65\x76\x50\x74\x72\x20\x3d\x20\x25\x6c\x6c\
\x75\x0a\0\x63\x75\x64\x61\x4d\x61\x6c\x6c\x6f\x63\x20\x52\x65\x74\x3a\x20\x70\
\x69\x64\x20\x3d\x20\x25\x75\x2c\x20\x28\x5f\x5f\x75\x36\x34\x29\x64\x65\x76\
\x50\x74\x72\x20\x3d\x20\x25\x6c\x6c\x75\x2c\x20\x61\x64\x64\x72\x20\x3d\x20\
\x25\x6c\x6c\x75\x0a\0\x63\x75\x64\x61\x46\x72\x65\x65\x20\x63\x61\x6c\x6c\x65\
\x64\x3a\x20\x70\x69\x64\x20\x3d\x20\x25\x75\x2c\x20\x28\x5f\x5f\x75\x36\x34\
\x29\x64\x65\x76\x50\x74\x72\x20\x3d\x20\x25\x6c\x6c\x75\x0a\0\x38\0\0\0\0\0\0\
\0\x01\0\0\0\x0f\0\0\0\xa8\0\0\0\0\0\0\0\x01\0\0\0\x0f\0\0\0\xd8\0\0\0\0\0\0\0\
\x01\0\0\0\x10\0\0\0\x40\x01\0\0\0\0\0\0\x01\0\0\0\x10\0\0\0\x48\0\0\0\0\0\0\0\
\x01\0\0\0\x10\0\0\0\xc0\x01\0\0\0\0\0\0\x01\0\0\0\x12\0\0\0\x10\x02\0\0\0\0\0\
\0\x01\0\0\0\x12\0\0\0\x08\x01\0\0\0\0\0\0\x01\0\0\0\x12\0\0\0\x40\x01\0\0\0\0\
\0\0\x01\0\0\0\x0f\0\0\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\xb4\x03\0\0\xb4\x03\0\
\0\x3c\x0a\0\0\0\0\0\0\0\0\0\x02\x03\0\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\
\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x01\0\0\0\x05\0\0\0\0\0\0\
\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x06\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\
\x02\0\0\0\x04\0\0\0\0\x10\0\0\0\0\0\0\0\0\0\x02\x08\0\0\0\x19\0\0\0\0\0\0\x08\
\x09\0\0\0\x1f\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\x04\0\0\x04\x20\0\0\
\0\x2c\0\0\0\x01\0\0\0\0\0\0\0\x31\0\0\0\x05\0\0\0\x40\0\0\0\x3d\0\0\0\x07\0\0\
\0\x80\0\0\0\x41\0\0\0\x07\0\0\0\xc0\0\0\0\x47\0\0\0\0\0\0\x0e\x0a\0\0\0\x01\0\
\0\0\0\0\0\0\0\0\0\x02\x0d\0\0\0\x57\0\0\0\0\0\0\x08\x0e\0\0\0\x5d\0\0\0\0\0\0\
\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\x04\0\0\x04\x20\0\0\0\x2c\0\0\0\x01\0\0\0\0\0\
\0\0\x31\0\0\0\x05\0\0\0\x40\0\0\0\x3d\0\0\0\x0c\0\0\0\x80\0\0\0\x41\0\0\0\x07\
\0\0\0\xc0\0\0\0\x70\0\0\0\0\0\0\x0e\x0f\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\x12\
\0\0\0\x81\0\0\0\0\0\0\x08\x13\0\0\0\0\0\0\0\x02\0\0\x04\x10\0\0\0\x8f\0\0\0\
\x0d\0\0\0\0\0\0\0\x93\0\0\0\x0d\0\0\0\x40\0\0\0\0\0\0\0\x04\0\0\x04\x20\0\0\0\
\x2c\0\0\0\x01\0\0\0\0\0\0\0\x31\0\0\0\x05\0\0\0\x40\0\0\0\x3d\0\0\0\x07\0\0\0\
\x80\0\0\0\x41\0\0\0\x11\0\0\0\xc0\0\0\0\x98\0\0\0\0\0\0\x0e\x14\0\0\0\x01\0\0\
\0\0\0\0\0\0\0\0\x02\x17\0\0\0\xa8\0\0\0\x15\0\0\x04\xa8\0\0\0\xb0\0\0\0\x18\0\
\0\0\0\0\0\0\xb4\0\0\0\x18\0\0\0\x40\0\0\0\xb8\0\0\0\x18\0\0\0\x80\0\0\0\xbc\0\
\0\0\x18\0\0\0\xc0\0\0\0\xc0\0\0\0\x18\0\0\0\0\x01\0\0\xc3\0\0\0\x18\0\0\0\x40\
\x01\0\0\xc6\0\0\0\x18\0\0\0\x80\x01\0\0\xca\0\0\0\x18\0\0\0\xc0\x01\0\0\xce\0\
\0\0\x18\0\0\0\0\x02\0\0\xd1\0\0\0\x18\0\0\0\x40\x02\0\0\xd4\0\0\0\x18\0\0\0\
\x80\x02\0\0\xd7\0\0\0\x18\0\0\0\xc0\x02\0\0\xda\0\0\0\x18\0\0\0\0\x03\0\0\xdd\
\0\0\0\x18\0\0\0\x40\x03\0\0\xe0\0\0\0\x18\0\0\0\x80\x03\0\0\xe3\0\0\0\x18\0\0\
\0\xc0\x03\0\0\xeb\0\0\0\x18\0\0\0\0\x04\0\0\xee\0\0\0\x18\0\0\0\x40\x04\0\0\
\xf1\0\0\0\x18\0\0\0\x80\x04\0\0\xf7\0\0\0\x18\0\0\0\xc0\x04\0\0\xfa\0\0\0\x18\
\0\0\0\0\x05\0\0\xfd\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\x01\0\0\x0d\
\x02\0\0\0\x0b\x01\0\0\x16\0\0\0\x0f\x01\0\0\x01\0\0\x0c\x19\0\0\0\x1b\x01\0\0\
\x01\0\0\x0c\x19\0\0\0\x2b\x01\0\0\x01\0\0\x0c\x19\0\0\0\x35\x01\0\0\0\0\0\x01\
\x01\0\0\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x1d\0\0\0\x04\0\0\0\x0d\0\0\0\
\x3a\x01\0\0\0\0\0\x0e\x1e\0\0\0\x01\0\0\0\x70\x09\0\0\x01\0\0\x0f\x0d\0\0\0\
\x1f\0\0\0\0\0\0\0\x0d\0\0\0\x78\x09\0\0\x03\0\0\x0f\x60\0\0\0\x0b\0\0\0\0\0\0\
\0\x20\0\0\0\x10\0\0\0\x20\0\0\0\x20\0\0\0\x15\0\0\0\x40\0\0\0\x20\0\0\0\0\x69\
\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\
\x5f\x5f\0\x5f\x5f\x75\x33\x32\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\
\x74\0\x74\x79\x70\x65\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x6b\x65\
\x79\0\x76\x61\x6c\x75\x65\0\x67\x70\x75\x5f\x6d\x65\x6d\x6f\x72\x79\x5f\x69\
\x6e\x66\x6f\0\x5f\x5f\x75\x36\x34\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\
\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\x63\x75\x64\x61\x5f\x6d\x61\x6c\x6c\x6f\x63\
\x5f\x68\x61\x73\x68\0\x6d\x61\x6c\x6c\x6f\x63\x5f\x69\x6e\x66\x6f\x5f\x74\0\
\x70\x74\x72\0\x73\x69\x7a\x65\0\x6d\x61\x6c\x6c\x6f\x63\x5f\x70\x74\x72\x5f\
\x69\x6e\x66\x6f\0\x70\x74\x5f\x72\x65\x67\x73\0\x72\x31\x35\0\x72\x31\x34\0\
\x72\x31\x33\0\x72\x31\x32\0\x62\x70\0\x62\x78\0\x72\x31\x31\0\x72\x31\x30\0\
\x72\x39\0\x72\x38\0\x61\x78\0\x63\x78\0\x64\x78\0\x73\x69\0\x64\x69\0\x6f\x72\
\x69\x67\x5f\x61\x78\0\x69\x70\0\x63\x73\0\x66\x6c\x61\x67\x73\0\x73\x70\0\x73\
\x73\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\0\x63\x74\x78\0\x63\
\x75\x64\x61\x5f\x6d\x61\x6c\x6c\x6f\x63\0\x63\x75\x64\x61\x5f\x6d\x61\x6c\x6c\
\x6f\x63\x5f\x72\x65\x74\0\x63\x75\x64\x61\x5f\x66\x72\x65\x65\0\x63\x68\x61\
\x72\0\x4c\x49\x43\x45\x4e\x53\x45\0\x2f\x6d\x6e\x74\x2f\x65\x2f\x50\x72\x6f\
\x67\x72\x61\x6d\x2f\x65\x62\x70\x66\x2d\x63\x75\x64\x61\x2d\x65\x78\x61\x6d\
\x70\x6c\x65\x73\x2f\x64\x65\x65\x70\x66\x6c\x6f\x77\x2e\x62\x70\x66\x2e\x63\0\
\x69\x6e\x74\x20\x42\x50\x46\x5f\x55\x50\x52\x4f\x42\x45\x28\x63\x75\x64\x61\
\x5f\x6d\x61\x6c\x6c\x6f\x63\x2c\x20\x76\x6f\x69\x64\x20\x2a\x2a\x64\x65\x76\
\x50\x74\x72\x2c\x20\x73\x69\x7a\x65\x5f\x74\x20\x73\x69\x7a\x65\x29\0\x20\x20\
\x20\x20\x5f\x5f\x75\x36\x34\x20\x69\x64\x20\x3d\x20\x62\x70\x66\x5f\x67\x65\
\x74\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x70\x69\x64\x5f\x74\x67\x69\x64\x28\
\x29\x3b\0\x20\x20\x20\x20\x5f\x5f\x75\x33\x32\x20\x74\x67\x69\x64\x20\x3d\x20\
\x28\x5f\x5f\x75\x33\x32\x29\x28\x69\x64\x20\x3e\x3e\x20\x33\x32\x29\x3b\0\x20\
\x20\x20\x20\x5f\x5f\x75\x33\x32\x2a\x20\x6d\x65\x6d\x5f\x64\x61\x74\x61\x20\
\x3d\x20\x28\x5f\x5f\x75\x33\x32\x2a\x29\x62\x70\x66\x5f\x6d\x61\x70\x5f\x6c\
\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\x6d\x28\x26\x67\x70\x75\x5f\x6d\x65\x6d\
\x6f\x72\x79\x5f\x69\x6e\x66\x6f\x2c\x20\x26\x74\x67\x69\x64\x29\x3b\0\x20\x20\
\x20\x20\x69\x66\x20\x28\x6d\x65\x6d\x5f\x64\x61\x74\x61\x29\x20\x7b\0\x20\x20\
\x20\x20\x20\x20\x20\x20\x2a\x6d\x65\x6d\x5f\x64\x61\x74\x61\x20\x2b\x3d\x20\
\x73\x69\x7a\x65\x3b\0\x20\x20\x20\x20\x20\x20\x20\x20\x5f\x5f\x75\x33\x32\x20\
\x6e\x65\x77\x5f\x6d\x65\x6d\x5f\x64\x61\x74\x61\x20\x3d\x20\x73\x69\x7a\x65\
\x3b\0\x20\x20\x20\x20\x20\x20\x20\x20\x62\x70\x66\x5f\x6d\x61\x70\x5f\x75\x70\
\x64\x61\x74\x65\x5f\x65\x6c\x65\x6d\x28\x26\x67\x70\x75\x5f\x6d\x65\x6d\x6f\
\x72\x79\x5f\x69\x6e\x66\x6f\x2c\x20\x26\x74\x67\x69\x64\x2c\x20\x26\x6e\x65\
\x77\x5f\x6d\x65\x6d\x5f\x64\x61\x74\x61\x2c\x20\x42\x50\x46\x5f\x41\x4e\x59\
\x29\x3b\0\x20\x20\x20\x20\x6d\x61\x6c\x6c\x6f\x63\x5f\x69\x6e\x66\x6f\x5f\x74\
\x2a\x20\x70\x74\x72\x5f\x64\x61\x74\x61\x20\x3d\x20\x28\x5f\x5f\x75\x36\x34\
\x2a\x29\x62\x70\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\
\x65\x6d\x28\x26\x6d\x61\x6c\x6c\x6f\x63\x5f\x70\x74\x72\x5f\x69\x6e\x66\x6f\
\x2c\x20\x26\x74\x67\x69\x64\x29\x3b\0\x20\x20\x20\x20\x69\x66\x20\x28\x70\x74\
\x72\x5f\x64\x61\x74\x61\x29\x20\x7b\0\x20\x20\x20\x20\x20\x20\x20\x20\x70\x74\
\x72\x5f\x64\x61\x74\x61\x2d\x3e\x73\x69\x7a\x65\x20\x3d\x20\x73\x69\x7a\x65\
\x3b\0\x20\x20\x20\x20\x20\x20\x20\x20\x70\x74\x72\x5f\x64\x61\x74\x61\x2d\x3e\
\x70\x74\x72\x20\x3d\x20\x28\x5f\x5f\x75\x36\x34\x29\x28\x64\x65\x76\x50\x74\
\x72\x29\x3b\0\x20\x20\x20\x20\x20\x20\x20\x20\x6d\x61\x6c\x6c\x6f\x63\x5f\x69\
\x6e\x66\x6f\x5f\x74\x20\x6e\x65\x77\x5f\x70\x74\x72\x5f\x64\x61\x74\x61\x20\
\x3d\x20\x7b\0\x20\x20\x20\x20\x20\x20\x20\x20\x62\x70\x66\x5f\x6d\x61\x70\x5f\
\x75\x70\x64\x61\x74\x65\x5f\x65\x6c\x65\x6d\x28\x26\x6d\x61\x6c\x6c\x6f\x63\
\x5f\x70\x74\x72\x5f\x69\x6e\x66\x6f\x2c\x20\x26\x74\x67\x69\x64\x2c\x20\x26\
\x6e\x65\x77\x5f\x70\x74\x72\x5f\x64\x61\x74\x61\x2c\x20\x42\x50\x46\x5f\x41\
\x4e\x59\x29\x3b\0\x20\x20\x20\x20\x69\x66\x20\x28\x6d\x65\x6d\x5f\x64\x61\x74\
\x61\x29\0\x20\x20\x20\x20\x20\x20\x20\x20\x6d\x5f\x64\x61\x74\x61\x20\x3d\x20\
\x2a\x6d\x65\x6d\x5f\x64\x61\x74\x61\x3b\0\x20\x20\x20\x20\x63\x6f\x6e\x73\x74\
\x20\x63\x68\x61\x72\x20\x66\x6d\x74\x5b\x5d\x20\x3d\x20\x22\x63\x75\x64\x61\
\x4d\x61\x6c\x6c\x6f\x63\x20\x63\x61\x6c\x6c\x65\x64\x3a\x20\x70\x69\x64\x20\
\x3d\x20\x25\x75\x2c\x20\x6d\x65\x6d\x5f\x64\x61\x74\x61\x20\x3d\x20\x25\x75\
\x2c\x20\x28\x5f\x5f\x75\x36\x34\x29\x64\x65\x76\x50\x74\x72\x20\x3d\x20\x25\
\x6c\x6c\x75\x5c\x6e\x22\x3b\0\x20\x20\x20\x20\x62\x70\x66\x5f\x74\x72\x61\x63\
\x65\x5f\x70\x72\x69\x6e\x74\x6b\x28\x66\x6d\x74\x2c\x20\x73\x69\x7a\x65\x6f\
\x66\x28\x66\x6d\x74\x29\x2c\x20\x74\x67\x69\x64\x2c\x20\x6d\x5f\x64\x61\x74\
\x61\x2c\x20\x28\x5f\x5f\x75\x36\x34\x29\x64\x65\x76\x50\x74\x72\x29\x3b\0\x69\
\x6e\x74\x20\x42\x50\x46\x5f\x55\x52\x45\x54\x50\x52\x4f\x42\x45\x28\x63\x75\
\x64\x61\x5f\x6d\x61\x6c\x6c\x6f\x63\x5f\x72\x65\x74\x2c\x20\x69\x6e\x74\x20\
\x72\x65\x74\x29\0\x20\x20\x20\x20\x69\x66\x20\x28\x72\x65\x74\x20\x21\x3d\x20\
\x30\x29\x20\x2f\x2f\x20\x4d\x61\x6c\x6c\x6f\x63\x20\x66\x61\x69\x6c\x65\x64\0\
\x20\x20\x20\x20\x6d\x61\x6c\x6c\x6f\x63\x5f\x69\x6e\x66\x6f\x5f\x74\x2a\x20\
\x6d\x61\x6c\x6c\x6f\x63\x5f\x69\x6e\x66\x6f\x5f\x64\x61\x74\x61\x20\x3d\x20\
\x28\x5f\x5f\x75\x36\x34\x2a\x29\x62\x70\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\
\x6b\x75\x70\x5f\x65\x6c\x65\x6d\x28\x26\x6d\x61\x6c\x6c\x6f\x63\x5f\x70\x74\
\x72\x5f\x69\x6e\x66\x6f\x2c\x20\x26\x74\x67\x69\x64\x29\x3b\0\x20\x20\x20\x20\
\x69\x66\x20\x28\x6d\x61\x6c\x6c\x6f\x63\x5f\x69\x6e\x66\x6f\x5f\x64\x61\x74\
\x61\x29\x20\x7b\0\x20\x20\x20\x20\x20\x20\x20\x20\x64\x65\x76\x50\x74\x72\x20\
\x3d\x20\x28\x76\x6f\x69\x64\x2a\x29\x28\x6d\x61\x6c\x6c\x6f\x63\x5f\x69\x6e\
\x66\x6f\x5f\x64\x61\x74\x61\x2d\x3e\x70\x74\x72\x29\x3b\0\x20\x20\x20\x20\x20\
\x20\x20\x20\x6d\x61\x6c\x6c\x6f\x63\x5f\x73\x69\x7a\x65\x20\x3d\x20\x6d\x61\
\x6c\x6c\x6f\x63\x5f\x69\x6e\x66\x6f\x5f\x64\x61\x74\x61\x2d\x3e\x73\x69\x7a\
\x65\x3b\0\x20\x20\x20\x20\x20\x20\x20\x20\x62\x70\x66\x5f\x70\x72\x6f\x62\x65\
\x5f\x72\x65\x61\x64\x5f\x75\x73\x65\x72\x28\x26\x64\x65\x76\x50\x74\x72\x5f\
\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x76\x6f\x69\x64\x2a\x29\x2c\x20\x64\x65\
\x76\x50\x74\x72\x29\x3b\0\x20\x20\x20\x20\x20\x20\x20\x20\x5f\x5f\x75\x36\x34\
\x20\x61\x64\x64\x72\x20\x3d\x20\x28\x5f\x5f\x75\x36\x34\x29\x28\x64\x65\x76\
\x50\x74\x72\x5f\x29\x3b\0\x20\x20\x20\x20\x20\x20\x20\x20\x63\x6f\x6e\x73\x74\
\x20\x63\x68\x61\x72\x20\x66\x6d\x74\x5b\x5d\x20\x3d\x20\x22\x63\x75\x64\x61\
\x4d\x61\x6c\x6c\x6f\x63\x20\x52\x65\x74\x3a\x20\x70\x69\x64\x20\x3d\x20\x25\
\x75\x2c\x20\x28\x5f\x5f\x75\x36\x34\x29\x64\x65\x76\x50\x74\x72\x20\x3d\x20\
\x25\x6c\x6c\x75\x2c\x20\x61\x64\x64\x72\x20\x3d\x20\x25\x6c\x6c\x75\x5c\x6e\
\x22\x3b\0\x20\x20\x20\x20\x20\x20\x20\x20\x62\x70\x66\x5f\x74\x72\x61\x63\x65\
\x5f\x70\x72\x69\x6e\x74\x6b\x28\x66\x6d\x74\x2c\x20\x73\x69\x7a\x65\x6f\x66\
\x28\x66\x6d\x74\x29\x2c\x20\x74\x67\x69\x64\x2c\x20\x6d\x61\x6c\x6c\x6f\x63\
\x5f\x69\x6e\x66\x6f\x5f\x64\x61\x74\x61\x2d\x3e\x70\x74\x72\x2c\x20\x61\x64\
\x64\x72\x29\x3b\0\x20\x20\x20\x20\x20\x20\x20\x20\x5f\x5f\x75\x33\x32\x2a\x20\
\x64\x61\x74\x61\x5f\x73\x69\x7a\x65\x20\x3d\x20\x28\x5f\x5f\x75\x33\x32\x2a\
\x29\x62\x70\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\
\x6d\x28\x26\x63\x75\x64\x61\x5f\x6d\x61\x6c\x6c\x6f\x63\x5f\x68\x61\x73\x68\
\x2c\x20\x26\x61\x64\x64\x72\x29\x3b\0\x20\x20\x20\x20\x20\x20\x20\x20\x69\x66\
\x20\x28\x64\x61\x74\x61\x5f\x73\x69\x7a\x65\x29\x20\x7b\0\x20\x20\x20\x20\x20\
\x20\x20\x20\x20\x20\x20\x20\x2a\x64\x61\x74\x61\x5f\x73\x69\x7a\x65\x20\x3d\
\x20\x6d\x61\x6c\x6c\x6f\x63\x5f\x73\x69\x7a\x65\x3b\0\x20\x20\x20\x20\x20\x20\
\x20\x20\x20\x20\x20\x20\x62\x70\x66\x5f\x6d\x61\x70\x5f\x75\x70\x64\x61\x74\
\x65\x5f\x65\x6c\x65\x6d\x28\x26\x63\x75\x64\x61\x5f\x6d\x61\x6c\x6c\x6f\x63\
\x5f\x68\x61\x73\x68\x2c\x20\x26\x61\x64\x64\x72\x2c\x20\x26\x6d\x61\x6c\x6c\
\x6f\x63\x5f\x73\x69\x7a\x65\x2c\x20\x42\x50\x46\x5f\x41\x4e\x59\x29\x3b\0\x69\
\x6e\x74\x20\x42\x50\x46\x5f\x55\x50\x52\x4f\x42\x45\x28\x63\x75\x64\x61\x5f\
\x66\x72\x65\x65\x2c\x20\x76\x6f\x69\x64\x20\x2a\x64\x65\x76\x50\x74\x72\x29\0\
\x20\x20\x20\x20\x5f\x5f\x75\x36\x34\x20\x61\x64\x64\x72\x20\x3d\x20\x28\x5f\
\x5f\x75\x36\x34\x29\x28\x64\x65\x76\x50\x74\x72\x29\x3b\0\x20\x20\x20\x20\x63\
\x6f\x6e\x73\x74\x20\x63\x68\x61\x72\x20\x66\x6d\x74\x5b\x5d\x20\x3d\x20\x22\
\x63\x75\x64\x61\x46\x72\x65\x65\x20\x63\x61\x6c\x6c\x65\x64\x3a\x20\x70\x69\
\x64\x20\x3d\x20\x25\x75\x2c\x20\x28\x5f\x5f\x75\x36\x34\x29\x64\x65\x76\x50\
\x74\x72\x20\x3d\x20\x25\x6c\x6c\x75\x5c\x6e\x22\x3b\0\x20\x20\x20\x20\x62\x70\
\x66\x5f\x74\x72\x61\x63\x65\x5f\x70\x72\x69\x6e\x74\x6b\x28\x66\x6d\x74\x2c\
\x20\x73\x69\x7a\x65\x6f\x66\x28\x66\x6d\x74\x29\x2c\x20\x74\x67\x69\x64\x2c\
\x20\x61\x64\x64\x72\x29\x3b\0\x20\x20\x20\x20\x5f\x5f\x75\x33\x32\x2a\x20\x6d\
\x61\x6c\x6c\x6f\x63\x5f\x73\x69\x7a\x65\x20\x3d\x20\x28\x5f\x5f\x75\x33\x32\
\x2a\x29\x62\x70\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\
\x65\x6d\x28\x26\x63\x75\x64\x61\x5f\x6d\x61\x6c\x6c\x6f\x63\x5f\x68\x61\x73\
\x68\x2c\x20\x26\x61\x64\x64\x72\x29\x3b\0\x20\x20\x20\x20\x69\x66\x20\x28\x6d\
\x61\x6c\x6c\x6f\x63\x5f\x73\x69\x7a\x65\x29\x20\x7b\0\x20\x20\x20\x20\x20\x20\
\x20\x20\x6d\x5f\x73\x69\x7a\x65\x20\x3d\x20\x2a\x6d\x61\x6c\x6c\x6f\x63\x5f\
\x73\x69\x7a\x65\x3b\0\x20\x20\x20\x20\x20\x20\x20\x20\x2a\x6d\x65\x6d\x5f\x64\
\x61\x74\x61\x20\x2d\x3d\x20\x6d\x5f\x73\x69\x7a\x65\x3b\0\x30\x3a\x31\x33\0\
\x30\x3a\x31\x34\0\x30\x3a\x31\x30\0\x6c\x69\x63\x65\x6e\x73\x65\0\x2e\x6d\x61\
\x70\x73\0\x75\x70\x72\x6f\x62\x65\x2f\x2f\x6d\x6e\x74\x2f\x65\x2f\x50\x72\x6f\
\x67\x72\x61\x6d\x2f\x65\x62\x70\x66\x2d\x63\x75\x64\x61\x2d\x65\x78\x61\x6d\
\x70\x6c\x65\x73\x2f\x63\x75\x64\x61\x2f\x63\x70\x6d\x65\x6d\x3a\x63\x75\x64\
\x61\x4d\x61\x6c\x6c\x6f\x63\0\x75\x72\x65\x74\x70\x72\x6f\x62\x65\x2f\x2f\x6d\
\x6e\x74\x2f\x65\x2f\x50\x72\x6f\x67\x72\x61\x6d\x2f\x65\x62\x70\x66\x2d\x63\
\x75\x64\x61\x2d\x65\x78\x61\x6d\x70\x6c\x65\x73\x2f\x63\x75\x64\x61\x2f\x63\
\x70\x6d\x65\x6d\x3a\x63\x75\x64\x61\x4d\x61\x6c\x6c\x6f\x63\0\x75\x70\x72\x6f\
\x62\x65\x2f\x2f\x6d\x6e\x74\x2f\x65\x2f\x50\x72\x6f\x67\x72\x61\x6d\x2f\x65\
\x62\x70\x66\x2d\x63\x75\x64\x61\x2d\x65\x78\x61\x6d\x70\x6c\x65\x73\x2f\x63\
\x75\x64\x61\x2f\x63\x70\x6d\x65\x6d\x3a\x63\x75\x64\x61\x46\x72\x65\x65\0\x9f\
\xeb\x01\0\x20\0\0\0\0\0\0\0\x34\0\0\0\x34\0\0\0\x4c\x04\0\0\x80\x04\0\0\x5c\0\
\0\0\x08\0\0\0\x7e\x09\0\0\x01\0\0\0\0\0\0\0\x1a\0\0\0\xbd\x09\0\0\x01\0\0\0\0\
\0\0\0\x1b\0\0\0\xff\x09\0\0\x01\0\0\0\0\0\0\0\x1c\0\0\0\x10\0\0\0\x7e\x09\0\0\
\x18\0\0\0\0\0\0\0\x42\x01\0\0\x73\x01\0\0\x05\xa0\0\0\x10\0\0\0\x42\x01\0\0\
\xab\x01\0\0\x10\xa8\0\0\x18\0\0\0\x42\x01\0\0\xd6\x01\0\0\x1d\xac\0\0\x20\0\0\
\0\x42\x01\0\0\xd6\x01\0\0\x0b\xac\0\0\x30\0\0\0\x42\x01\0\0\0\0\0\0\0\0\0\0\
\x38\0\0\0\x42\x01\0\0\xfa\x01\0\0\x1f\xb4\0\0\x58\0\0\0\x42\x01\0\0\x46\x02\0\
\0\x09\xb8\0\0\x60\0\0\0\x42\x01\0\0\x5a\x02\0\0\x13\xbc\0\0\x80\0\0\0\x42\x01\
\0\0\x75\x02\0\0\x0f\xc4\0\0\xa8\0\0\0\x42\x01\0\0\x98\x02\0\0\x09\xc8\0\0\xd0\
\0\0\0\x42\x01\0\0\xe6\x02\0\0\x27\xd4\0\0\xf0\0\0\0\x42\x01\0\0\x3a\x03\0\0\
\x09\xd8\0\0\xf8\0\0\0\x42\x01\0\0\x4e\x03\0\0\x18\xe0\0\0\0\x01\0\0\x42\x01\0\
\0\x6d\x03\0\0\x17\xdc\0\0\x10\x01\0\0\x42\x01\0\0\x96\x03\0\0\x26\xe8\0\0\x28\
\x01\0\0\x42\x01\0\0\0\0\0\0\0\0\0\0\x40\x01\0\0\x42\x01\0\0\xbd\x03\0\0\x09\
\xf8\0\0\x68\x01\0\0\x42\x01\0\0\x0b\x04\0\0\x09\x08\x01\0\x70\x01\0\0\x42\x01\
\0\0\x1d\x04\0\0\x12\x0c\x01\0\x80\x01\0\0\x42\x01\0\0\x39\x04\0\0\x10\x10\x01\
\0\x48\x02\0\0\x42\x01\0\0\x96\x04\0\0\x05\x14\x01\0\x58\x02\0\0\x42\x01\0\0\0\
\0\0\0\0\0\0\0\x60\x02\0\0\x42\x01\0\0\x96\x04\0\0\x05\x14\x01\0\x78\x02\0\0\
\x42\x01\0\0\x73\x01\0\0\x05\xa0\0\0\xbd\x09\0\0\x1a\0\0\0\0\0\0\0\x42\x01\0\0\
\xdb\x04\0\0\x05\x2c\x01\0\x08\0\0\0\x42\x01\0\0\xab\x01\0\0\x10\x34\x01\0\x10\
\0\0\0\x42\x01\0\0\xd6\x01\0\0\x1d\x38\x01\0\x18\0\0\0\x42\x01\0\0\xd6\x01\0\0\
\x0b\x38\x01\0\x20\0\0\0\x42\x01\0\0\xab\x01\0\0\x10\x34\x01\0\x30\0\0\0\x42\
\x01\0\0\x07\x05\0\0\x09\x44\x01\0\x40\0\0\0\x42\x01\0\0\x2a\x05\0\0\x2f\x58\
\x01\0\x60\0\0\0\x42\x01\0\0\x86\x05\0\0\x09\x64\x01\0\x68\0\0\0\x42\x01\0\0\
\xa2\x05\0\0\x2c\x68\x01\0\x70\0\0\0\x42\x01\0\0\xd3\x05\0\0\x29\x6c\x01\0\x78\
\0\0\0\x42\x01\0\0\xd3\x05\0\0\x15\x6c\x01\0\x88\0\0\0\x42\x01\0\0\xa2\x05\0\0\
\x2c\x68\x01\0\x90\0\0\0\x42\x01\0\0\x01\x06\0\0\x09\x78\x01\0\xa8\0\0\0\x42\
\x01\0\0\x3f\x06\0\0\x1e\x7c\x01\0\xb0\0\0\0\x42\x01\0\0\x3f\x06\0\0\x0f\x7c\
\x01\0\xc0\0\0\0\x42\x01\0\0\x66\x06\0\0\x14\x84\x01\0\x80\x01\0\0\x42\x01\0\0\
\xc2\x06\0\0\x44\x88\x01\0\x88\x01\0\0\x42\x01\0\0\xc2\x06\0\0\x09\x88\x01\0\
\x98\x01\0\0\x42\x01\0\0\xa2\x05\0\0\x2c\x68\x01\0\xa0\x01\0\0\x42\x01\0\0\xc2\
\x06\0\0\x09\x88\x01\0\xb8\x01\0\0\x42\x01\0\0\xa2\x05\0\0\x2c\x68\x01\0\xc0\
\x01\0\0\x42\x01\0\0\x11\x07\0\0\x24\x90\x01\0\xd8\x01\0\0\x42\x01\0\0\x63\x07\
\0\0\x0d\x94\x01\0\xe0\x01\0\0\x42\x01\0\0\x7c\x07\0\0\x18\x98\x01\0\xf8\x01\0\
\0\x42\x01\0\0\xa2\x07\0\0\x0d\xa0\x01\0\x30\x02\0\0\x42\x01\0\0\xdb\x04\0\0\
\x05\x2c\x01\0\xff\x09\0\0\x11\0\0\0\0\0\0\0\x42\x01\0\0\xf4\x07\0\0\x05\xc0\
\x01\0\x08\0\0\0\x42\x01\0\0\xab\x01\0\0\x10\xc8\x01\0\x10\0\0\0\x42\x01\0\0\
\xd6\x01\0\0\x1d\xcc\x01\0\x18\0\0\0\x42\x01\0\0\xd6\x01\0\0\x0b\xcc\x01\0\x20\
\0\0\0\x42\x01\0\0\x1c\x08\0\0\x0b\xd8\x01\0\x38\0\0\0\x42\x01\0\0\x3e\x08\0\0\
\x10\xe0\x01\0\xd0\0\0\0\x42\x01\0\0\0\0\0\0\0\0\0\0\xd8\0\0\0\x42\x01\0\0\x8a\
\x08\0\0\x05\xe4\x01\0\0\x01\0\0\x42\x01\0\0\0\0\0\0\0\0\0\0\x08\x01\0\0\x42\
\x01\0\0\xbe\x08\0\0\x22\xec\x01\0\x20\x01\0\0\x42\x01\0\0\x0e\x09\0\0\x09\xf4\
\x01\0\x28\x01\0\0\x42\x01\0\0\x25\x09\0\0\x12\xf8\x01\0\x38\x01\0\0\x42\x01\0\
\0\0\0\0\0\0\0\0\0\x40\x01\0\0\x42\x01\0\0\xfa\x01\0\0\x1f\x04\x02\0\x58\x01\0\
\0\x42\x01\0\0\x46\x02\0\0\x09\x08\x02\0\x60\x01\0\0\x42\x01\0\0\x44\x09\0\0\
\x13\x0c\x02\0\x78\x01\0\0\x42\x01\0\0\xf4\x07\0\0\x05\xc0\x01\0\x10\0\0\0\x7e\
\x09\0\0\x02\0\0\0\0\0\0\0\x17\0\0\0\x61\x09\0\0\0\0\0\0\x08\0\0\0\x17\0\0\0\
\x66\x09\0\0\0\0\0\0\xbd\x09\0\0\x01\0\0\0\0\0\0\0\x17\0\0\0\x6b\x09\0\0\0\0\0\
\0\xff\x09\0\0\x01\0\0\0\0\0\0\0\x17\0\0\0\x66\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x03\0\0\0\x20\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x71\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x09\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\xb8\x02\0\0\0\0\0\0\xf8\x01\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\
\x18\0\0\0\0\0\0\0\x11\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb0\
\x04\0\0\0\0\0\0\x88\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x50\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x38\x07\0\0\0\0\
\0\0\x40\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x92\
\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x78\x09\0\0\0\0\0\0\x88\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xcf\0\0\0\x01\0\
\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0b\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd7\0\0\0\x01\0\0\0\x03\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x10\x0b\0\0\0\0\0\0\x60\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xdd\0\0\0\x01\0\0\0\x32\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x70\x0b\0\0\0\0\0\0\xb0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\
\0\0\x01\0\0\0\0\0\0\0\x99\x01\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x20\x0c\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x02\0\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\
\x10\0\0\0\0\0\0\0\xdc\x01\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x60\
\x0c\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x02\0\0\0\x04\0\0\0\x08\0\0\0\0\0\0\0\x10\0\
\0\0\0\0\0\0\x22\x02\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x90\x0c\0\
\0\0\0\0\0\x20\0\0\0\0\0\0\0\x02\0\0\0\x05\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\
\0\0\0\x63\x02\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb0\x0c\0\0\0\0\0\
\0\x08\x0e\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x68\
\x02\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb8\x1a\0\0\0\0\0\0\xfc\x04\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct deepflow_bpf *deepflow_bpf::open(const struct bpf_object_open_opts *opts) { return deepflow_bpf__open_opts(opts); }
struct deepflow_bpf *deepflow_bpf::open_and_load() { return deepflow_bpf__open_and_load(); }
int deepflow_bpf::load(struct deepflow_bpf *skel) { return deepflow_bpf__load(skel); }
int deepflow_bpf::attach(struct deepflow_bpf *skel) { return deepflow_bpf__attach(skel); }
void deepflow_bpf::detach(struct deepflow_bpf *skel) { deepflow_bpf__detach(skel); }
void deepflow_bpf::destroy(struct deepflow_bpf *skel) { deepflow_bpf__destroy(skel); }
const void *deepflow_bpf::elf_bytes(size_t *sz) { return deepflow_bpf__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
deepflow_bpf__assert(struct deepflow_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __DEEPFLOW_BPF_SKEL_H__ */
