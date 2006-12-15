#include "types.h"
#include "layout.h"
#include "sd.h"

/**
 * init_system_file_sd
 *
 * NTFS 3.1 - System files security decriptors
 * =====================================================
 *
 * Create the security descriptor for system file number @sys_file_no and
 * return a pointer to the descriptor.
 *
 * $MFT, $MFTMirr, $LogFile, $AttrDef, $Bitmap, $Boot, $BadClus, and $UpCase
 * are the same.
 *
 * $Volume, $Quota, and system files 0xb-0xf are the same. They are almost the
 * same as the above, the only difference being that the two SIDs present in
 * the DACL grant GENERIC_WRITE and GENERIC_READ equivalent privileges while
 * the above only grant GENERIC_READ equivalent privileges.
 *
 * Root directory system file (".") is different altogether.
 *
 * The sd is returned in *@sd_val and has length *@sd_val_len.
 *
 * Do NOT free *@sd_val as it is static memory. This also means that you can
 * only use *@sd_val until the next call to this function.
 */
void init_system_file_sd(int sys_file_no, u8 **sd_val, int *sd_val_len)
{
	static u8 sd_array[0x68];
	SECURITY_DESCRIPTOR_RELATIVE *sd;
	ACL *acl;
	ACCESS_ALLOWED_ACE *aa_ace;
	SID *sid;

	if (sys_file_no < 0) {
		*sd_val = NULL;
		*sd_val_len = 0;
		return;
	}
	*sd_val = sd_array;
	sd = (SECURITY_DESCRIPTOR_RELATIVE*)&sd_array;
	sd->revision = 1;
	sd->alignment = 0;
	sd->control = SE_SELF_RELATIVE | SE_DACL_PRESENT;
	*sd_val_len = 0x64;
	sd->owner = const_cpu_to_le32(0x48);
	sd->group = const_cpu_to_le32(0x54);
	sd->sacl = const_cpu_to_le32(0);
	sd->dacl = const_cpu_to_le32(0x14);
	/*
	 * Now at offset 0x14, as specified in the security descriptor, we have
	 * the DACL.
	 */
	acl = (ACL*)((char*)sd + le32_to_cpu(sd->dacl));
	acl->revision = 2;
	acl->alignment1 = 0;
	acl->size = const_cpu_to_le16(0x34);
	acl->ace_count = const_cpu_to_le16(2);
	acl->alignment2 = const_cpu_to_le16(0);
	/*
	 * Now at offset 0x1c, just after the DACL's ACL, we have the first
	 * ACE of the DACL. The type of the ACE is access allowed.
	 */
	aa_ace = (ACCESS_ALLOWED_ACE*)((char*)acl + sizeof(ACL));
	aa_ace->type = ACCESS_ALLOWED_ACE_TYPE;
	aa_ace->flags = 0;
	aa_ace->size = const_cpu_to_le16(0x14);
	switch (sys_file_no) {
	case FILE_AttrDef:
	case FILE_Boot:
		aa_ace->mask = SYNCHRONIZE | STANDARD_RIGHTS_READ |
			FILE_READ_ATTRIBUTES | FILE_READ_EA | FILE_READ_DATA;
		break;
	default:
		aa_ace->mask = SYNCHRONIZE | STANDARD_RIGHTS_WRITE |
			FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES |
			FILE_WRITE_EA | FILE_READ_EA | FILE_APPEND_DATA |
			FILE_WRITE_DATA | FILE_READ_DATA;
		break;
	}
	aa_ace->sid.revision = 1;
	aa_ace->sid.sub_authority_count = 1;
	aa_ace->sid.identifier_authority.value[0] = 0;
	aa_ace->sid.identifier_authority.value[1] = 0;
	aa_ace->sid.identifier_authority.value[2] = 0;
	aa_ace->sid.identifier_authority.value[3] = 0;
	aa_ace->sid.identifier_authority.value[4] = 0;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	aa_ace->sid.identifier_authority.value[5] = 5;
	aa_ace->sid.sub_authority[0] =
			const_cpu_to_le32(SECURITY_LOCAL_SYSTEM_RID);
	/*
	 * Now at offset 0x30 within security descriptor, just after the first
	 * ACE of the DACL. All system files, except the root directory, have
	 * a second ACE.
	 */
	/* The second ACE of the DACL. Type is access allowed. */
	aa_ace = (ACCESS_ALLOWED_ACE*)((char*)aa_ace +
			le16_to_cpu(aa_ace->size));
	aa_ace->type = ACCESS_ALLOWED_ACE_TYPE;
	aa_ace->flags = 0;
	aa_ace->size = const_cpu_to_le16(0x18);
	/* Only $AttrDef and $Boot behave differently to everything else. */
	switch (sys_file_no) {
	case FILE_AttrDef:
	case FILE_Boot:
		aa_ace->mask = SYNCHRONIZE | STANDARD_RIGHTS_READ |
				FILE_READ_ATTRIBUTES | FILE_READ_EA |
				FILE_READ_DATA;
		break;
	default:
		aa_ace->mask = SYNCHRONIZE | STANDARD_RIGHTS_READ |
				FILE_WRITE_ATTRIBUTES |
				FILE_READ_ATTRIBUTES | FILE_WRITE_EA |
				FILE_READ_EA | FILE_APPEND_DATA |
				FILE_WRITE_DATA | FILE_READ_DATA;
		break;
	}
	aa_ace->sid.revision = 1;
	aa_ace->sid.sub_authority_count = 2;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	aa_ace->sid.identifier_authority.value[0] = 0;
	aa_ace->sid.identifier_authority.value[1] = 0;
	aa_ace->sid.identifier_authority.value[2] = 0;
	aa_ace->sid.identifier_authority.value[3] = 0;
	aa_ace->sid.identifier_authority.value[4] = 0;
	aa_ace->sid.identifier_authority.value[5] = 5;
	aa_ace->sid.sub_authority[0] =
			const_cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	aa_ace->sid.sub_authority[1] =
			const_cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);
	/*
	 * Now at offset 0x48 into the security descriptor, as specified in the
	 * security descriptor, we now have the owner SID.
	 */
	sid = (SID*)((char*)sd + le32_to_cpu(sd->owner));
	sid->revision = 1;
	sid->sub_authority_count = 1;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	sid->identifier_authority.value[0] = 0;
	sid->identifier_authority.value[1] = 0;
	sid->identifier_authority.value[2] = 0;
	sid->identifier_authority.value[3] = 0;
	sid->identifier_authority.value[4] = 0;
	sid->identifier_authority.value[5] = 5;
	sid->sub_authority[0] = const_cpu_to_le32(SECURITY_LOCAL_SYSTEM_RID);
	/*
	 * Now at offset 0x54 into the security descriptor, as specified in the
	 * security descriptor, we have the group SID.
	 */
	sid = (SID*)((char*)sd + le32_to_cpu(sd->group));
	sid->revision = 1;
	sid->sub_authority_count = 2;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	sid->identifier_authority.value[0] = 0;
	sid->identifier_authority.value[1] = 0;
	sid->identifier_authority.value[2] = 0;
	sid->identifier_authority.value[3] = 0;
	sid->identifier_authority.value[4] = 0;
	sid->identifier_authority.value[5] = 5;
	sid->sub_authority[0] = const_cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	sid->sub_authority[1] = const_cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);
}

/**
 * init_root_sd_31
 *
 * creates the security_descriptor for the root folder on ntfs 3.1.
 * It is very long; lots of ACE's at first, then large pieces of zeroes;
 * the owner user/group is near the end. On a partition created with
 * w2k3 the owner user/group at the end is surrounded by 'garbage', which I
 * yet do not understand. Here I have replaced the 'garbage' with
 * zeros, which seems to work. Chkdsk does not add the 'garbage', nor alter
 * this security descriptor in any way.
 */
void init_root_sd_31(u8 **sd_val, int *sd_val_len)
{
	SECURITY_DESCRIPTOR_RELATIVE *sd;
	ACL *acl;
	ACCESS_ALLOWED_ACE *ace;
	SID *sid;

	static char sd_array[0x102c];
	*sd_val_len = 0x102c;
	*sd_val = (u8*)&sd_array;

	//security descriptor relative
	sd = (SECURITY_DESCRIPTOR_RELATIVE*)sd_array;
	sd->revision = 0x01;
	sd->alignment = 0x00;
	sd->control = SE_SELF_RELATIVE | SE_DACL_PRESENT;
	sd->owner = const_cpu_to_le32(0x1014);
	sd->group = const_cpu_to_le32(0x1020);
	sd->sacl = const_cpu_to_le32(0x00);
	sd->dacl = const_cpu_to_le32(0x14);

	//acl
	acl = (ACL*)((u8*)sd + sizeof(SECURITY_DESCRIPTOR_RELATIVE));
	acl->revision = 0x02;
	acl->alignment1 = 0x00;
	acl->size = const_cpu_to_le16(0x1000);
	acl->ace_count = const_cpu_to_le16(0x07);
	acl->alignment2 = const_cpu_to_le16(0x00);

	//ace1
	ace = (ACCESS_ALLOWED_ACE*)((u8*)acl + sizeof(ACL));
	ace->type = 0x00;
	ace->flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
	ace->size = const_cpu_to_le16(0x18);
	ace->mask = STANDARD_RIGHTS_ALL | FILE_WRITE_ATTRIBUTES |
			 FILE_LIST_DIRECTORY | FILE_WRITE_DATA |
			 FILE_ADD_SUBDIRECTORY | FILE_READ_EA | FILE_WRITE_EA |
			 FILE_TRAVERSE | FILE_DELETE_CHILD |
			 FILE_READ_ATTRIBUTES;

	ace->sid.revision = 0x01;
	ace->sid.sub_authority_count = 0x02;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	ace->sid.identifier_authority.value[0] = 0;
	ace->sid.identifier_authority.value[1] = 0;
	ace->sid.identifier_authority.value[2] = 0;
	ace->sid.identifier_authority.value[3] = 0;
	ace->sid.identifier_authority.value[4] = 0;
	ace->sid.identifier_authority.value[5] = 5;
	ace->sid.sub_authority[0] =
			const_cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	ace->sid.sub_authority[1] = const_cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);

	//ace2
	ace = (ACCESS_ALLOWED_ACE*)((u8*)ace + le16_to_cpu(ace->size));
	ace->type = 0x00;
	ace->flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
	ace->size = const_cpu_to_le16(0x14);
	ace->mask = STANDARD_RIGHTS_ALL | FILE_WRITE_ATTRIBUTES |
			 FILE_LIST_DIRECTORY | FILE_WRITE_DATA |
			 FILE_ADD_SUBDIRECTORY | FILE_READ_EA | FILE_WRITE_EA |
			 FILE_TRAVERSE | FILE_DELETE_CHILD |
			 FILE_READ_ATTRIBUTES;
	ace->sid.revision = 0x01;
	ace->sid.sub_authority_count = 0x01;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	ace->sid.identifier_authority.value[0] = 0;
	ace->sid.identifier_authority.value[1] = 0;
	ace->sid.identifier_authority.value[2] = 0;
	ace->sid.identifier_authority.value[3] = 0;
	ace->sid.identifier_authority.value[4] = 0;
	ace->sid.identifier_authority.value[5] = 5;
	ace->sid.sub_authority[0] =
			const_cpu_to_le32(SECURITY_LOCAL_SYSTEM_RID);

	//ace3
	ace = (ACCESS_ALLOWED_ACE*)((u8*)ace + le16_to_cpu(ace->size));
	ace->type = 0x00;
	ace->flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE |
			INHERIT_ONLY_ACE;
	ace->size = const_cpu_to_le16(0x14);
	ace->mask = const_cpu_to_le32(0x10000000);
	ace->sid.revision = 0x01;
	ace->sid.sub_authority_count = 0x01;
	/* SECURITY_CREATOR_SID_AUTHORITY (S-1-3) */
	ace->sid.identifier_authority.value[0] = 0;
	ace->sid.identifier_authority.value[1] = 0;
	ace->sid.identifier_authority.value[2] = 0;
	ace->sid.identifier_authority.value[3] = 0;
	ace->sid.identifier_authority.value[4] = 0;
	ace->sid.identifier_authority.value[5] = 3;
	ace->sid.sub_authority[0] =
			const_cpu_to_le32(SECURITY_CREATOR_OWNER_RID);

	//ace4
	ace = (ACCESS_ALLOWED_ACE*)((u8*)ace + le16_to_cpu(ace->size));
	ace->type = 0x00;
	ace->flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
	ace->size = const_cpu_to_le16(0x18);
	ace->mask = const_cpu_to_le32(0x1200A9);
	ace->sid.revision = 0x01;
	ace->sid.sub_authority_count = 0x02;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	ace->sid.identifier_authority.value[0] = 0;
	ace->sid.identifier_authority.value[1] = 0;
	ace->sid.identifier_authority.value[2] = 0;
	ace->sid.identifier_authority.value[3] = 0;
	ace->sid.identifier_authority.value[4] = 0;
	ace->sid.identifier_authority.value[5] = 5;
	ace->sid.sub_authority[0] =
			const_cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	ace->sid.sub_authority[1] = const_cpu_to_le32(DOMAIN_ALIAS_RID_USERS);

	//ace5
	ace = (ACCESS_ALLOWED_ACE*)((char*)ace + le16_to_cpu(ace->size));
	ace->type = 0x00;
	ace->flags = CONTAINER_INHERIT_ACE;
	ace->size = const_cpu_to_le16(0x18);
	ace->mask = const_cpu_to_le32(0x04);
	ace->sid.revision = 0x01;
	ace->sid.sub_authority_count = 0x02;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	ace->sid.identifier_authority.value[0] = 0;
	ace->sid.identifier_authority.value[1] = 0;
	ace->sid.identifier_authority.value[2] = 0;
	ace->sid.identifier_authority.value[3] = 0;
	ace->sid.identifier_authority.value[4] = 0;
	ace->sid.identifier_authority.value[5] = 5;
	ace->sid.sub_authority[0] =
			const_cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	ace->sid.sub_authority[1] = const_cpu_to_le32(DOMAIN_ALIAS_RID_USERS);

	//ace6
	ace = (ACCESS_ALLOWED_ACE*)((u8*)ace + le16_to_cpu(ace->size));
	ace->type = 0x00;
	ace->flags = CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE;
	ace->size = const_cpu_to_le16(0x18);
	ace->mask = const_cpu_to_le32(0x02);
	ace->sid.revision = 0x01;
	ace->sid.sub_authority_count = 0x02;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	ace->sid.identifier_authority.value[0] = 0;
	ace->sid.identifier_authority.value[1] = 0;
	ace->sid.identifier_authority.value[2] = 0;
	ace->sid.identifier_authority.value[3] = 0;
	ace->sid.identifier_authority.value[4] = 0;
	ace->sid.identifier_authority.value[5] = 5;
	ace->sid.sub_authority[0] =
			const_cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	ace->sid.sub_authority[1] = const_cpu_to_le32(DOMAIN_ALIAS_RID_USERS);

	//ace7
	ace = (ACCESS_ALLOWED_ACE*)((u8*)ace + le16_to_cpu(ace->size));
	ace->type = 0x00;
	ace->flags = 0x00;
	ace->size = const_cpu_to_le16(0x14);
	ace->mask = const_cpu_to_le32(0x1200A9);
	ace->sid.revision = 0x01;
	ace->sid.sub_authority_count = 0x01;
	/* SECURITY_WORLD_SID_AUTHORITY (S-1-1) */
	ace->sid.identifier_authority.value[0] = 0;
	ace->sid.identifier_authority.value[1] = 0;
	ace->sid.identifier_authority.value[2] = 0;
	ace->sid.identifier_authority.value[3] = 0;
	ace->sid.identifier_authority.value[4] = 0;
	ace->sid.identifier_authority.value[5] = 1;
	ace->sid.sub_authority[0] = const_cpu_to_le32(SECURITY_WORLD_RID);

	//owner sid
	sid = (SID*)((char*)sd + le32_to_cpu(sd->owner));
	sid->revision = 0x01;
	sid->sub_authority_count = 0x01;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	sid->identifier_authority.value[0] = 0;
	sid->identifier_authority.value[1] = 0;
	sid->identifier_authority.value[2] = 0;
	sid->identifier_authority.value[3] = 0;
	sid->identifier_authority.value[4] = 0;
	sid->identifier_authority.value[5] = 5;
	sid->sub_authority[0] = const_cpu_to_le32(SECURITY_LOCAL_SYSTEM_RID);

	//group sid
	sid = (SID*)((char*)sd + le32_to_cpu(sd->group));
	sid->revision = 0x01;
	sid->sub_authority_count = 0x01;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	sid->identifier_authority.value[0] = 0;
	sid->identifier_authority.value[1] = 0;
	sid->identifier_authority.value[2] = 0;
	sid->identifier_authority.value[3] = 0;
	sid->identifier_authority.value[4] = 0;
	sid->identifier_authority.value[5] = 5;
	sid->sub_authority[0] = const_cpu_to_le32(SECURITY_LOCAL_SYSTEM_RID);
}

/**
 * init_secure_31(char **r, int size);
 *
 * NTFS 3.1 - System files security decriptors
 * ===========================================
 * Create the security descriptor entries in $SDS data stream like they
 * are in a partition, newly formatted with windows 2003
 */
void init_secure_31(char *sd_val)
{
	SECURITY_DESCRIPTOR_HEADER *sds;
	SECURITY_DESCRIPTOR_RELATIVE *sd;
	ACL *acl;
	ACCESS_ALLOWED_ACE *ace;
	SID *sid;

/*
 * security descriptor #1
 */
	//header
	sds = (SECURITY_DESCRIPTOR_HEADER*)((char*)sd_val);
	sds->hash = const_cpu_to_le32(0xF80312F0);
	sds->security_id = const_cpu_to_le32(0x0100);
	sds->offset = const_cpu_to_le64(0x00);
	sds->length = const_cpu_to_le32(0x7C);
	//security descriptor relative
	sd = (SECURITY_DESCRIPTOR_RELATIVE*)((char*)sds +
			sizeof(SECURITY_DESCRIPTOR_HEADER));
	sd->revision = 0x01;
	sd->alignment = 0x00;
	sd->control = SE_SELF_RELATIVE | SE_DACL_PRESENT;
	sd->owner = const_cpu_to_le32(0x48);
	sd->group = const_cpu_to_le32(0x58);
	sd->sacl = const_cpu_to_le32(0x00);
	sd->dacl = const_cpu_to_le32(0x14);

	//acl
	acl = (ACL*)((char*)sd + sizeof(SECURITY_DESCRIPTOR_RELATIVE));
	acl->revision = 0x02;
	acl->alignment1 = 0x00;
	acl->size = const_cpu_to_le16(0x34);
	acl->ace_count = const_cpu_to_le16(0x02);
	acl->alignment2 = 0x00;

	//ace1
	ace = (ACCESS_ALLOWED_ACE*)((char*)acl + sizeof(ACL));
	ace->type = 0x00;
	ace->flags = 0x00;
	ace->size = const_cpu_to_le16(0x14);
	ace->mask = const_cpu_to_le32(0x120089);
	ace->sid.revision = 0x01;
	ace->sid.sub_authority_count = 0x01;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	ace->sid.identifier_authority.value[0] = 0;
	ace->sid.identifier_authority.value[1] = 0;
	ace->sid.identifier_authority.value[2] = 0;
	ace->sid.identifier_authority.value[3] = 0;
	ace->sid.identifier_authority.value[4] = 0;
	ace->sid.identifier_authority.value[5] = 5;
	ace->sid.sub_authority[0] =
			const_cpu_to_le32(SECURITY_LOCAL_SYSTEM_RID);
	//ace2
	ace = (ACCESS_ALLOWED_ACE*)((char*)ace + le16_to_cpu(ace->size));
	ace->type = 0x00;
	ace->flags = 0x00;
	ace->size = const_cpu_to_le16(0x18);
	ace->mask = const_cpu_to_le32(0x120089);
	ace->sid.revision = 0x01;
	ace->sid.sub_authority_count = 0x02;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	ace->sid.identifier_authority.value[0] = 0;
	ace->sid.identifier_authority.value[1] = 0;
	ace->sid.identifier_authority.value[2] = 0;
	ace->sid.identifier_authority.value[3] = 0;
	ace->sid.identifier_authority.value[4] = 0;
	ace->sid.identifier_authority.value[5] = 5;
	ace->sid.sub_authority[0] =
		const_cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	ace->sid.sub_authority[1] =
		const_cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);

	//owner sid
	sid = (SID*)((char*)sd + le32_to_cpu(sd->owner));
	sid->revision = 0x01;
	sid->sub_authority_count = 0x02;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	sid->identifier_authority.value[0] = 0;
	sid->identifier_authority.value[1] = 0;
	sid->identifier_authority.value[2] = 0;
	sid->identifier_authority.value[3] = 0;
	sid->identifier_authority.value[4] = 0;
	sid->identifier_authority.value[5] = 5;
	sid->sub_authority[0] =
		const_cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	sid->sub_authority[1] =
		const_cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);
	//group sid
	sid = (SID*)((char*)sd + le32_to_cpu(sd->group));
	sid->revision = 0x01;
	sid->sub_authority_count = 0x02;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	sid->identifier_authority.value[0] = 0;
	sid->identifier_authority.value[1] = 0;
	sid->identifier_authority.value[2] = 0;
	sid->identifier_authority.value[3] = 0;
	sid->identifier_authority.value[4] = 0;
	sid->identifier_authority.value[5] = 5;
	sid->sub_authority[0] =
		const_cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	sid->sub_authority[1] =
		const_cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);
/*
 * security descriptor #2
 */
	//header
	sds = (SECURITY_DESCRIPTOR_HEADER*)((char*)sd_val + 0x80);
	sds->hash = const_cpu_to_le32(0xB32451);
	sds->security_id = const_cpu_to_le32(0x0101);
	sds->offset = const_cpu_to_le64(0x80);
	sds->length = const_cpu_to_le32(0x7C);

	//security descriptor relative
	sd = (SECURITY_DESCRIPTOR_RELATIVE*)((char*)sds +
		 sizeof(SECURITY_DESCRIPTOR_HEADER));
	sd->revision = 0x01;
	sd->alignment = 0x00;
	sd->control = SE_SELF_RELATIVE | SE_DACL_PRESENT;
	sd->owner = const_cpu_to_le32(0x48);
	sd->group = const_cpu_to_le32(0x58);
	sd->sacl = const_cpu_to_le32(0x00);
	sd->dacl = const_cpu_to_le32(0x14);

	//acl
	acl = (ACL*)((char*)sd + sizeof(SECURITY_DESCRIPTOR_RELATIVE));
	acl->revision = 0x02;
	acl->alignment1 = 0x00;
	acl->size = const_cpu_to_le16(0x34);
	acl->ace_count = const_cpu_to_le16(0x02);
	acl->alignment2 = 0x00;

	//ace1
	ace = (ACCESS_ALLOWED_ACE*)((char*)acl + sizeof(ACL));
	ace->type = 0x00;
	ace->flags = 0x00;
	ace->size = const_cpu_to_le16(0x14);
	ace->mask = const_cpu_to_le32(0x12019F);
	ace->sid.revision = 0x01;
	ace->sid.sub_authority_count = 0x01;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	ace->sid.identifier_authority.value[0] = 0;
	ace->sid.identifier_authority.value[1] = 0;
	ace->sid.identifier_authority.value[2] = 0;
	ace->sid.identifier_authority.value[3] = 0;
	ace->sid.identifier_authority.value[4] = 0;
	ace->sid.identifier_authority.value[5] = 5;
	ace->sid.sub_authority[0] =
		const_cpu_to_le32(SECURITY_LOCAL_SYSTEM_RID);
	//ace2
	ace = (ACCESS_ALLOWED_ACE*)((char*)ace + le16_to_cpu(ace->size));
	ace->type = 0x00;
	ace->flags = 0x00;
	ace->size = const_cpu_to_le16(0x18);
	ace->mask = const_cpu_to_le32(0x12019F);
	ace->sid.revision = 0x01;
	ace->sid.sub_authority_count = 0x02;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	ace->sid.identifier_authority.value[0] = 0;
	ace->sid.identifier_authority.value[1] = 0;
	ace->sid.identifier_authority.value[2] = 0;
	ace->sid.identifier_authority.value[3] = 0;
	ace->sid.identifier_authority.value[4] = 0;
	ace->sid.identifier_authority.value[5] = 5;
	ace->sid.sub_authority[0] =
		const_cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	ace->sid.sub_authority[1] =
		const_cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);

	//owner sid
	sid = (SID*)((char*)sd + le32_to_cpu(sd->owner));
	sid->revision = 0x01;
	sid->sub_authority_count = 0x02;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	sid->identifier_authority.value[0] = 0;
	sid->identifier_authority.value[1] = 0;
	sid->identifier_authority.value[2] = 0;
	sid->identifier_authority.value[3] = 0;
	sid->identifier_authority.value[4] = 0;
	sid->identifier_authority.value[5] = 5;
	sid->sub_authority[0] =
		const_cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	sid->sub_authority[1] =
		const_cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);

	//group sid
	sid = (SID*)((char*)sd + le32_to_cpu(sd->group));
	sid->revision = 0x01;
	sid->sub_authority_count = 0x02;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	sid->identifier_authority.value[0] = 0;
	sid->identifier_authority.value[1] = 0;
	sid->identifier_authority.value[2] = 0;
	sid->identifier_authority.value[3] = 0;
	sid->identifier_authority.value[4] = 0;
	sid->identifier_authority.value[5] = 5;
	sid->sub_authority[0] =
		const_cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	sid->sub_authority[1] =
		const_cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);

	return;
}
