use crate::utils::*;
use std::convert::From;
#[derive(Debug)]
pub struct CoffFileHeader {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}
impl CoffFileHeader {
    pub fn build(contents: &Vec<u8>) -> CoffFileHeader {
        let Machine = vec2u16(&contents[..2]);
        let NumberOfSections = vec2u16(&contents[2..4]);
        let TimeDateStamp = vec2u32(&contents[4..8]);
        let PointerToSymbolTable = vec2u32(&contents[8..12]);
        let NumberOfSymbols = vec2u32(&contents[12..16]);
        let SizeOfOptionalHeader = vec2u16(&contents[16..18]);
        let Characteristics = vec2u16(&contents[18..20]);
        CoffFileHeader {
            Machine,
            NumberOfSections,
            TimeDateStamp,
            PointerToSymbolTable,
            NumberOfSymbols,
            SizeOfOptionalHeader,
            Characteristics,
        }
    }
    pub fn empty() -> CoffFileHeader {
        CoffFileHeader {
            Machine: 0,
            NumberOfSections: 0,
            TimeDateStamp: 0,
            PointerToSymbolTable: 0,
            NumberOfSymbols: 0,
            SizeOfOptionalHeader: 0,
            Characteristics: 0,
        }
    }
}

#[derive(Debug)]
pub struct SectionHeader {
    // pub Name:u64,
    pub Name: Vec<u8>,
    pub VirtualSize: u32,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}
impl SectionHeader {
    pub fn get(coff_file: &Vec<u8>, index: &usize) -> SectionHeader {
        let coff_header_size: usize = 20;
        let coff_section_header_size: usize = 40;
        let section_header = SectionHeader::build(
            &coff_file[(coff_header_size + index * coff_section_header_size) as usize..].to_vec(),
        );
        section_header
    }
    pub fn build(contents: &Vec<u8>) -> SectionHeader {
        let Name = Vec::from(&contents[..8]);
        let VirtualSize = vec2u32(&contents[8..12]);
        let VirtualAddress = vec2u32(&contents[12..16]);
        let SizeOfRawData = vec2u32(&contents[16..20]);
        let PointerToRawData = vec2u32(&contents[20..24]);
        let PointerToRelocations = vec2u32(&contents[24..28]);
        let PointerToLinenumbers = vec2u32(&contents[28..32]);
        let NumberOfRelocations = vec2u16(&contents[32..34]);
        let NumberOfLinenumbers = vec2u16(&contents[34..36]);
        let Characteristics = vec2u32(&contents[36..40]);
        SectionHeader {
            Name,
            VirtualSize,
            VirtualAddress,
            SizeOfRawData,
            PointerToRawData,
            PointerToRelocations,
            PointerToLinenumbers,
            NumberOfRelocations,
            NumberOfLinenumbers,
            Characteristics,
        }
    }
    pub fn empty() -> SectionHeader {
        SectionHeader {
            Name: Vec::new(),
            VirtualSize: 0,
            VirtualAddress: 0,
            SizeOfRawData: 0,
            PointerToRawData: 0,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: 0,
        }
    }
}

#[derive(Debug)]
pub struct SymbolTable {
    pub Name: Vec<u8>,
    pub Value: u32,
    pub SectionNumber: u16,
    pub Type: u16,
    pub StorageClass: u8,
    pub NumberOfAuxSymbols: u8,
}

impl SymbolTable {
    pub fn get(coff_file: &Vec<u8>, pointer: &u32, index: &usize) -> SymbolTable {
        let coff_symbol_table_size: usize = 18;
        let symbol_table = SymbolTable::build(
            &coff_file[*pointer as usize + index * coff_symbol_table_size..].to_vec(),
        );
        symbol_table
    }
    pub fn build(contents: &Vec<u8>) -> SymbolTable {
        let Name = Vec::from(&contents[..8]);
        let Value = vec2u32(&contents[8..12]);
        let SectionNumber = vec2u16(&contents[12..14]);
        let Type = vec2u16(&contents[14..16]);
        let StorageClass = contents[16];
        let NumberOfAuxSymbols = contents[17];
        SymbolTable {
            Name,
            Value,
            SectionNumber,
            Type,
            StorageClass,
            NumberOfAuxSymbols,
        }
    }
    pub fn empty() -> SymbolTable {
        SymbolTable {
            Name: Vec::new(),
            Value: 0,
            SectionNumber: 0,
            Type: 0,
            StorageClass: 0,
            NumberOfAuxSymbols: 0,
        }
    }
}

#[derive(Debug)]
pub struct RelocationTable {
    pub VirtualAddress: u32,
    pub SymbolTableIndex: u32,
    pub Type: u16,
}

impl RelocationTable {
    pub fn get(coff_file: &Vec<u8>, pointer: &u32, index: &usize) -> RelocationTable {
        let coff_reloc_table_size = 10;
        let reloc = RelocationTable::build(
            &coff_file[*pointer as usize + coff_reloc_table_size * index..].to_vec(),
        );
        reloc
    }
    pub fn build(contents: &Vec<u8>) -> RelocationTable {
        let VirtualAddress = vec2u32(&contents[..4]);
        let SymbolTableIndex = vec2u32(&contents[4..8]);
        let Type = vec2u16(&contents[8..10]);
        RelocationTable {
            VirtualAddress,
            SymbolTableIndex,
            Type,
        }
    }
    pub fn empty() -> RelocationTable {
        RelocationTable {
            VirtualAddress: 0,
            SymbolTableIndex: 0,
            Type: 0,
        }
    }
}

pub const IMAGE_SYM_CLASS_END_OF_FUNCTION: i8 = -1;
pub const IMAGE_SYM_CLASS_NULL: i8 = 0x0000;
pub const IMAGE_SYM_CLASS_AUTOMATIC: i8 = 0x0001;
pub const IMAGE_SYM_CLASS_EXTERNAL: i8 = 0x0002;
pub const IMAGE_SYM_CLASS_STATIC: i8 = 0x0003;
pub const IMAGE_SYM_CLASS_REGISTER: i8 = 0x0004;
pub const IMAGE_SYM_CLASS_EXTERNAL_DEF: i8 = 0x0005;
pub const IMAGE_SYM_CLASS_LABEL: i8 = 0x0006;
pub const IMAGE_SYM_CLASS_UNDEFINED_LABEL: i8 = 0x0007;
pub const IMAGE_SYM_CLASS_MEMBER_OF_STRUCT: i8 = 0x0008;
pub const IMAGE_SYM_CLASS_ARGUMENT: i8 = 0x0009;
pub const IMAGE_SYM_CLASS_STRUCT_TAG: i8 = 0x000A;
pub const IMAGE_SYM_CLASS_MEMBER_OF_UNION: i8 = 0x000B;
pub const IMAGE_SYM_CLASS_UNION_TAG: i8 = 0x000C;
pub const IMAGE_SYM_CLASS_TYPE_DEFINITION: i8 = 0x000D;
pub const IMAGE_SYM_CLASS_UNDEFINED_STATIC: i8 = 0x000E;
pub const IMAGE_SYM_CLASS_ENUM_TAG: i8 = 0x000F;
pub const IMAGE_SYM_CLASS_MEMBER_OF_ENUM: i8 = 0x0010;
pub const IMAGE_SYM_CLASS_REGISTER_PARAM: i8 = 0x0011;
pub const IMAGE_SYM_CLASS_BIT_FIELD: i8 = 0x0012;
pub const IMAGE_SYM_CLASS_FAR_EXTERNAL: i8 = 0x0044;
pub const IMAGE_SYM_CLASS_BLOCK: i8 = 0x0064;
pub const IMAGE_SYM_CLASS_FUNCTION: i8 = 0x0065;
pub const IMAGE_SYM_CLASS_END_OF_STRUCT: i8 = 0x0066;
pub const IMAGE_SYM_CLASS_FILE: i8 = 0x0067;
pub const IMAGE_SYM_CLASS_SECTION: i8 = 0x0068;
pub const IMAGE_SYM_CLASS_WEAK_EXTERNAL: i8 = 0x0069;
pub const IMAGE_SYM_CLASS_CLR_TOKEN: i8 = 0x006B;

pub const IMAGE_REL_AMD64_ABSOLUTE: u16 = 0x0000;
pub const IMAGE_REL_AMD64_ADDR64: u16 = 0x0001;
pub const IMAGE_REL_AMD64_ADDR32: u16 = 0x0002;
pub const IMAGE_REL_AMD64_ADDR32NB: u16 = 0x0003;
pub const IMAGE_REL_AMD64_REL32: u16 = 0x0004;
pub const IMAGE_REL_AMD64_REL32_1: u16 = 0x0005;
pub const IMAGE_REL_AMD64_REL32_2: u16 = 0x0006;
pub const IMAGE_REL_AMD64_REL32_3: u16 = 0x0007;
pub const IMAGE_REL_AMD64_REL32_4: u16 = 0x0008;
pub const IMAGE_REL_AMD64_REL32_5: u16 = 0x0009;
pub const IMAGE_REL_AMD64_SECTION: u16 = 0x000A;
pub const IMAGE_REL_AMD64_SECREL: u16 = 0x000B;
pub const IMAGE_REL_AMD64_SECREL7: u16 = 0x000C;
pub const IMAGE_REL_AMD64_TOKEN: u16 = 0x000D;
pub const IMAGE_REL_AMD64_SREL32: u16 = 0x000E;
pub const IMAGE_REL_AMD64_PAIR: u16 = 0x000F;
pub const IMAGE_REL_AMD64_SSPAN32: u16 = 0x0010;
