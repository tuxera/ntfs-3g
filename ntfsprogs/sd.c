#include "types.h"
#include "layout.h"

/**
 * init_system_file_sd
 *
 * NTFS 1.2 - System files security decriptors
 * ===========================================
 *
 * Create the security descriptor for system file number @sys_file_no and
 * return a pointer to the descriptor.
 *
 * $MFT, $MFTMirr, $LogFile, $AttrDef, $Bitmap, $Boot, $BadClus, and $UpCase
 * are the same.
 *
 * $Volume, $Quota, and system files 0xb-0xf are the same. They are almost the
 * same as the above, the only difference being that the two SIDs present in
 * the DACL grant GENERIC_WRITE and GENERIC_READ equivalent priviledges while
 * the above only grant GENERIC_READ equivalent priviledges. (For some reason
 * the flags for GENERIC_READ/GENERIC_WRITE are not set by NT4, even though
 * the permissions are equivalent, so we comply.
 *
 * Root directory system file (".") is different altogether.
 *
 * The sd is recturned in *@sd_val and has length *@sd_val_len.
 *
 * Do NOT free *@sd_val as it is static memory. This also means that you can
 * only use *@sd_val until the next call to this function.
 *
 */
void init_system_file_sd(int sys_file_no, char **sd_val, int *sd_val_len)
{
	static char sd_array[0x68];
	SECURITY_DESCRIPTOR_RELATIVE *sd;
	ACL *acl;
	ACCESS_ALLOWED_ACE *aa_ace;
	SID *sid;

	if (sys_file_no < 0 || sys_file_no > 0xf) {
		*sd_val = NULL;
		*sd_val_len = 0;
		return;
	}
	*sd_val = (char*)&sd_array;
	sd = (SECURITY_DESCRIPTOR_RELATIVE*)&sd_array;
	sd->revision = 1;
	sd->alignment = 0;
	sd->control = SE_SELF_RELATIVE | SE_DACL_PRESENT;
	if (sys_file_no == FILE_root) {
		*sd_val_len = 0x50;
		sd->owner = cpu_to_le32(0x30);
		sd->group = cpu_to_le32(0x40);
	} else {
		*sd_val_len = 0x68;
		sd->owner = cpu_to_le32(0x48);
		sd->group = cpu_to_le32(0x58);
	}
	sd->sacl = cpu_to_le32(0);
	sd->dacl = cpu_to_le32(0x14);
	/*
	 * Now at offset 0x14, as specified in the security descriptor, we have
	 * the DACL.
	 */
	acl = (ACL*)((char*)sd + le32_to_cpu(sd->dacl));
	acl->revision = 2;
	acl->alignment1 = 0;
	if (sys_file_no == FILE_root) {
		acl->size = cpu_to_le16(0x1c);
		acl->ace_count = cpu_to_le16(1);
	} else {
		acl->size = cpu_to_le16(0x34);
		acl->ace_count = cpu_to_le16(2);
	}
	acl->alignment2 = cpu_to_le16(0);
	/*
	 * Now at offset 0x1c, just after the DACL's ACL, we have the first
	 * ACE of the DACL. The type of the ACE is access allowed.
	 */
	aa_ace = (ACCESS_ALLOWED_ACE*)((char*)acl + sizeof(ACL));
	aa_ace->type = ACCESS_ALLOWED_ACE_TYPE;
	if (sys_file_no == FILE_root)
		aa_ace->flags = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
	else
		aa_ace->flags = 0;
	aa_ace->size = cpu_to_le16(0x14);
	switch (sys_file_no) {
	case FILE_MFT:		case FILE_MFTMirr:	case FILE_LogFile:
	case FILE_AttrDef:	case FILE_Bitmap:	case FILE_Boot:
	case FILE_BadClus:	case FILE_UpCase:
		aa_ace->mask = SYNCHRONIZE | STANDARD_RIGHTS_READ |
			FILE_READ_ATTRIBUTES | FILE_READ_EA | FILE_READ_DATA;
		break;
	case FILE_Volume:	case FILE_Secure:	case 0xb ... 0xf:
		aa_ace->mask = SYNCHRONIZE | STANDARD_RIGHTS_WRITE |
			FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES |
			FILE_WRITE_EA | FILE_READ_EA | FILE_APPEND_DATA |
			FILE_WRITE_DATA | FILE_READ_DATA;
		break;
	case FILE_root:
		aa_ace->mask = STANDARD_RIGHTS_ALL | FILE_WRITE_ATTRIBUTES |
			FILE_READ_ATTRIBUTES | FILE_DELETE_CHILD |
			FILE_TRAVERSE | FILE_WRITE_EA | FILE_READ_EA |
			FILE_ADD_SUBDIRECTORY | FILE_ADD_FILE |
			FILE_LIST_DIRECTORY;
		break;
	}
	aa_ace->sid.revision = 1;
	aa_ace->sid.sub_authority_count = 1;
	aa_ace->sid.identifier_authority.value[0] = 0;
	aa_ace->sid.identifier_authority.value[1] = 0;
	aa_ace->sid.identifier_authority.value[2] = 0;
	aa_ace->sid.identifier_authority.value[3] = 0;
	aa_ace->sid.identifier_authority.value[4] = 0;
	if (sys_file_no == FILE_root) {
		/* SECURITY_WORLD_SID_AUTHORITY (S-1-1) */
		aa_ace->sid.identifier_authority.value[5] = 1;
		aa_ace->sid.sub_authority[0] =
				cpu_to_le32(SECURITY_WORLD_RID);
		/* This is S-1-1-0, the WORLD_SID. */
	} else {
		/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
		aa_ace->sid.identifier_authority.value[5] = 5;
		aa_ace->sid.sub_authority[0] =
				cpu_to_le32(SECURITY_LOCAL_SYSTEM_RID);
	}
	/*
	 * Now at offset 0x30 within security descriptor, just after the first
	 * ACE of the DACL. All system files, except the root directory, have
	 * a second ACE.
	 */
	if (sys_file_no != FILE_root) {
		/* The second ACE of the DACL. Type is access allowed. */
		aa_ace = (ACCESS_ALLOWED_ACE*)((char*)aa_ace +
				le16_to_cpu(aa_ace->size));
		aa_ace->type = ACCESS_ALLOWED_ACE_TYPE;
		aa_ace->flags = 0;
		aa_ace->size = cpu_to_le16(0x18);
		switch (sys_file_no) {
		case FILE_MFT:		case FILE_MFTMirr:
		case FILE_LogFile:	case FILE_AttrDef:
		case FILE_Bitmap:	case FILE_Boot:
		case FILE_BadClus:	case FILE_UpCase:
			aa_ace->mask = SYNCHRONIZE | STANDARD_RIGHTS_READ |
					FILE_READ_ATTRIBUTES | FILE_READ_EA |
					FILE_READ_DATA;
			break;
		case FILE_Volume:	case FILE_Secure:
		case 0xb ... 0xf:
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
				cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
		aa_ace->sid.sub_authority[1] =
				cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);
		/* Now at offset 0x48 into the security descriptor. */
	}
	/* As specified in the security descriptor, we now have the owner SID.*/
	sid = (SID*)((char*)sd + le32_to_cpu(sd->owner));
	sid->revision = 1;
	sid->sub_authority_count = 2;
	/* SECURITY_NT_SID_AUTHORITY (S-1-5) */
	sid->identifier_authority.value[0] = 0;
	sid->identifier_authority.value[1] = 0;
	sid->identifier_authority.value[2] = 0;
	sid->identifier_authority.value[3] = 0;
	sid->identifier_authority.value[4] = 0;
	sid->identifier_authority.value[5] = 5;
	sid->sub_authority[0] = cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	sid->sub_authority[1] = cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);
	/*
	 * Now at offset 0x40 or 0x58 (root directory and the other system
	 * files, respectively) into the security descriptor, as specified in
	 * the security descriptor, we have the group SID.
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
	sid->sub_authority[0] = cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	sid->sub_authority[1] = cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);
}

