/* Device tree blob parsing and writing
 *
 * Based on specs from: https://www.devicetree.org/specifications/ [v0.3-rc2]
 * 
 * To read a device tree blob binary into a parsed device tree structure:
 * 1. call DeviceTreeBlob::from_slice() using a byte slice of the blob in memory
 * 2. call to_parsed() on the DeviceTreeBlob object to create a parsed DeviceTree
 * 
 * The parsed DeviceTree can be queried and modified.
 * 
 * To write a parsed device tree structure to memory as a device tree blob binary:
 * 1. Create a new DeviceTree using new() and populate it, or use an existing DeviceTree
 * 2. call DeviceTree::to_blob()
 * 
 * The parsed device tree is designed to be safely iterated over, searched, cloned, and
 * modified by Rust code. Note: This code ignores empty nodes with no properties - FIXME?
 * 
 * This does not require the standard library, but it does require a heap allocator.
 * 
 * (c) Chris Williams, 2019-2020.
 *
 * See LICENSE for usage and copying.
 */
#![cfg_attr(not(test), no_std)]

#[cfg(test)] extern crate std;
#[cfg(test)] mod tests;

#[macro_use]
extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::collections::btree_map::{self, BTreeMap};
use core::mem::size_of;

extern crate hashbrown;
use hashbrown::hash_map::{HashMap, self};

extern crate byterider;
use byterider::{Bytes, Ordering};

/* we support any DTB backwards compatible to this spec version number */
const LOWEST_SUPPORTED_VERSION: u32 = 2;
const DTB_VERSION: u32 = 17; /* follow version 17 of the DT specification */

/* DTB token ID numbers, hardwired into the spec */
const FDT_BEGIN_NODE:   u32 = 0x00000001;
const FDT_END_NODE:     u32 = 0x00000002;
const FDT_PROP:         u32 = 0x00000003;
const FDT_NOP:          u32 = 0x00000004;
const FDT_END:          u32 = 0x00000009;

/* DTB header magic numbers */
const DTB_MAGIC: u32 = 0xd00dfeed;

/* defaults for #address-cells and #size-cells from the specification */
const DEFAULTADDRESSCELLS: usize = 2;
const DEFAULTSIZECELLS:    usize = 1;

/* useful macros for rounding an address up to the next word boundaries */
macro_rules! align_to_next_u32 { ($a:expr) => ($a = ($a & !3) + 4); }
macro_rules! align_to_next_u8  { ($a:expr) => ($a = $a + 1);        }

/* returns true if address is aligned to a 32-bit word boundary */
macro_rules! is_aligned_u32    { ($a:expr) => (($a & 3) == 0);      }

/* nodes in paths are separated by a / */
const DEVICETREESEPARATOR: &'static str = "/";

/* define parsing errors / results */
#[derive(Debug)]
pub enum DeviceTreeError
{
    /* DTB parsing errors */
    CannotConvert,
    FailedMagicCheck,
    ReachedEnd,
    ReachedUnexpectedEnd,
    TokenUnaligned,
    SkippedToken,
    BadToken(u32),
    MissingRootNode,

    /* device tree processing */
    NotFound,
    WidthUnsupported,
    OutOfBoundsWrite,
    DeviceFailure
}

/* define the header for a raw device tree blob */
#[allow(dead_code)]
pub struct DeviceTreeBlob
{
    /* the tree blob header */
    magic: u32,
    totalsize: u32,
    off_dt_struct: u32,
    off_dt_strings: u32,
    off_mem_rsvmap: u32,
    version: u32,
    last_comp_version: u32,
    boot_cpuid_phys: u32,
    size_dt_strings: u32,
    size_dt_struct: u32,

    /* a copy of the raw bytes in the blob */
    bytes: Bytes
}

impl DeviceTreeBlob
{
    /* return true if this looks like legit DTB data, or false if not */
    pub fn valid_magic_check(&self) -> bool
    {
        if self.magic != DTB_MAGIC || self.last_comp_version > LOWEST_SUPPORTED_VERSION
        {
            return false;
        }

        return true;
    }

    /* create a basic DeviceTreeBlob structure from a byte slice of a device tree blob.
    Note: this will create a copy of the byte slice on the heap.
    <= device tree blob as a byte slice
    => a DeviceTreeBlob object, or error core for failure */
    pub fn from_slice(blob: &[u8]) -> Result<DeviceTreeBlob, DeviceTreeError>
    {
        let mut bytes = Bytes::from_slice(blob);
        bytes.set_ordering(Ordering::BigEndian); /* device tree blobs are stored in BE */
        
        let dtb = DeviceTreeBlob
        {
            magic:              bytes.read_u32(0 * 4).unwrap(),
            totalsize:          bytes.read_u32(1 * 4).unwrap(),
            off_dt_struct:      bytes.read_u32(2 * 4).unwrap(),
            off_dt_strings:     bytes.read_u32(3 * 4).unwrap(),
            off_mem_rsvmap:     bytes.read_u32(4 * 4).unwrap(),
            version:            bytes.read_u32(5 * 4).unwrap(),
            last_comp_version:  bytes.read_u32(6 * 4).unwrap(),
            boot_cpuid_phys:    bytes.read_u32(7 * 4).unwrap(),
            size_dt_strings:    bytes.read_u32(8 * 4).unwrap(),
            size_dt_struct:     bytes.read_u32(9 * 4).unwrap(),
            bytes:              bytes
        };

        match dtb.valid_magic_check()
        {
            true => Ok(dtb),
            false => Err(DeviceTreeError::FailedMagicCheck)
        }
    }

    /* convert this DTB binary into a structured device tree that can be safely walked by Rust code
    => device tree structure, or error code for failure */
    pub fn to_parsed(&self) -> Result<DeviceTree, DeviceTreeError>
    {
        /* force a magic check */
        if self.valid_magic_check() == false { return Err(DeviceTreeError::FailedMagicCheck); }

        let mut dt = DeviceTree::new();

        let mut offset = self.off_dt_struct as usize;
        let mut path = Vec::<String>::new();

        /* walk through the tokens in the blob. offset is automatically incremented
        and path is automatically updated as we iterate through sub-nodes into the blob.
        pass offset and path each iteration, and all the information we need is returned
        in a DeviceTreeBlobTokenParsed structure */
        loop
        {
            match self.parse_token(&mut offset, &mut path)
            {
                /* ...and add entries to the structured version */
                Ok(entry) => dt.edit_property(&entry.full_path, &entry.property, entry.value),

                /* these aren't errors and shouldn't be treated fatally */
                Err(DeviceTreeError::ReachedEnd) => break,
                Err(DeviceTreeError::SkippedToken) => (),

                /* ...though these are fatal for the parser */
                Err(e) => return Err(e)
            };
        }

        Ok(dt)
    }

    /* parse a token in the blob and return an entry to add to the structured device tree
       => offset = token location in bytes from the start of the blob. this is automatically
                   updated to the next token after parsing, unless the end of the tree is reached.
                   this offset value must be u32-word aligned.
          current_parent_path = a vector of strings of node names for the current parent node. this is
                                automatically updated as we traverse sub-nodes
       <= returns entry to add to the tree, or an error code
    */
    fn parse_token(&self, offset: &mut usize, current_parent_path: &mut Vec<String>) -> Result<DeviceTreeBlobTokenParsed, DeviceTreeError>
    {
        /* ensure alignment */
        if is_aligned_u32!(*offset) == false
        {
            return Err(DeviceTreeError::TokenUnaligned)
        }

        let token = match self.bytes.read_u32(*offset)
        {
            Some(t) => t,
            None => return Err(DeviceTreeError::ReachedUnexpectedEnd) /* stop parsing when out of bounds */
        };

        match token
        {
            /* mark the start and end of a node. a node contains any number of properties
            and any number of child nodes */
            FDT_BEGIN_NODE =>
            {
                /* immediately after this word is a null-terminated string for the node's name.
                extract that from memory and then add to the current parent node path */
                align_to_next_u32!(*offset);
                let node_name = self.get_string(*offset);
                *offset = *offset + node_name.len();
                current_parent_path.push(node_name);

                /* move onto the next aligned token */
                align_to_next_u32!(*offset);
                return Err(DeviceTreeError::SkippedToken); 
            },
            FDT_END_NODE =>
            {
                /* step back up the path list */
                current_parent_path.pop();

                /* move onto the next aligned token */
                align_to_next_u32!(*offset);
                return Err(DeviceTreeError::SkippedToken);
            },

            /* describe a node property */
            FDT_PROP =>
            {
                /* immediately following the token is a 32-bit length parameter
                and then a 32-bit offset into the string table for the property's name.
                then follows length number of bytes of data belonging to the property */
                align_to_next_u32!(*offset);
                let length = match self.bytes.read_u32(*offset)
                {
                    Some(l) => l,
                    None => return Err(DeviceTreeError::ReachedUnexpectedEnd)
                };

                align_to_next_u32!(*offset);
                let string_offset = match self.bytes.read_u32(*offset)
                {
                    Some(so) => so,
                    None => return Err(DeviceTreeError::ReachedUnexpectedEnd)
                };

                /* skip offset past the string offset header, then either generate
                an empty property or one with the property's data copied into it */
                align_to_next_u32!(*offset);
                let value = match length
                {
                    0 => DeviceTreeProperty::Empty,
                    _ =>
                    {
                        let mut array = Vec::<u8>::new();
                        for _ in 0..length
                        {
                            if let Some(byte) = self.bytes.read_u8(*offset)
                            {
                                array.push(byte);
                                align_to_next_u8!(*offset);
                            }
                            else
                            {
                                return Err(DeviceTreeError::ReachedUnexpectedEnd);
                            }
                        }

                        /* don't forget to align to a boundary if necessary */
                        if is_aligned_u32!(*offset) == false
                        {
                            align_to_next_u32!(*offset);
                        }

                        DeviceTreeProperty::Bytes(array)
                    }
                };

                /* handle the special case of the root node being '/' */
                let full_path = match current_parent_path.len()
                {
                    0 => String::new(),
                    1 => String::from(DEVICETREESEPARATOR),
                    _ => current_parent_path.join(DEVICETREESEPARATOR)
                };

                return Ok(DeviceTreeBlobTokenParsed
                {
                    full_path,
                    value,
                    property: self.get_string((string_offset + self.off_dt_strings) as usize)
                });
            },

            /* this marks the end of the blob data structure */
            FDT_END => return Err(DeviceTreeError::ReachedEnd),

            /* handle NOPs and bad tokens */
            FDT_NOP =>
            {
                /* skip this token and try the next */
                align_to_next_u32!(*offset);
                return Err(DeviceTreeError::SkippedToken);
            },

            t => return Err(DeviceTreeError::BadToken(t))
        };
    }

    /* return a copy of a null-terminated string at offset bytes from the base address of the blob */
    fn get_string(&self, offset: usize) -> String
    {
        let mut count = 0;
        let mut characters = String::new();

        /* copy string one byte at a time until we hit a null byte or a colon ":" character.
        this assumes the string is using basic 7-bit ASCII as defined in the specification.
        colons are not allowed in node nor property names, but may be used to add parameters
        after a property name in a /chosen subnode. we ignore the colon and any
        subsequent parameters. */
        loop
        {
            match self.bytes.read_u8(offset + count)
            {
                Some(c) => match c
                {
                    /* stop at null or colon bytes (see above comment) */
                    b'\0' | b':' => break,
                    /* accept all other characters */
                    c =>
                    {
                        characters.push(c as char);
                        align_to_next_u8!(count);
                    }
                },
                None => break 
            }
        }

        characters
    }
}

/* describe a parsed token as an entry for the structured device tree */
struct DeviceTreeBlobTokenParsed
{
    full_path: String,
    property: String,
    value: DeviceTreeProperty
}

/* convert the contents of a property into various formats. the DTB parser
will store the property's data as Bytes() or Empty(). To get it into
a more useful format, call one of the as_...() functions in DeviceTreeProperty */
#[derive(Clone, Debug)]
pub enum DeviceTreeProperty
{
    Empty,
    Bytes(Vec<u8>),
    
    MultipleUnsignedInt64_64(Vec<(u64, u64)>),
    MultipleUnsignedInt64_32(Vec<(u64, u32)>),
    MultipleUnsignedInt32_32(Vec<(u32, u32)>),

    MultipleUnsignedInt64(Vec<u64>),
    MultipleUnsignedInt32(Vec<u32>),

    UnsignedInt32(u32),
    Text(String),
    MultipleText(Vec<String>),
}

impl DeviceTreeProperty
{
    /* get the raw size of a property when stored in memory.
    as per the specification, strings (Text) include a NULL byte
    and a stringlist (MultipleText) has a single terminating NULL byte */
    pub fn size(&self) -> usize
    {
        match self
        {
            DeviceTreeProperty::Empty => 0,
            DeviceTreeProperty::Bytes(v) => v.len(),
            DeviceTreeProperty::MultipleUnsignedInt64_64(v) => v.len() * 2 * size_of::<u64>(),
            DeviceTreeProperty::MultipleUnsignedInt64_32(v) => v.len() * (size_of::<u64>() + size_of::<u32>()),
            DeviceTreeProperty::MultipleUnsignedInt32_32(v) => v.len() * 2 * size_of::<u32>(),
            DeviceTreeProperty::MultipleUnsignedInt64(v) => v.len() * size_of::<u64>(),
            DeviceTreeProperty::MultipleUnsignedInt32(v) => v.len() * size_of::<u64>(),
            DeviceTreeProperty::UnsignedInt32(_) => size_of::<u32>(),
            DeviceTreeProperty::Text(s) => s.len() + 1, /* include NULL byte */
            DeviceTreeProperty::MultipleText(v) =>
            {
                let mut total = 0;
                for s in v
                {
                    total = total + s.len();
                }
                total + 1 /* include the final NULL byte */
            }
        }
    }

    /* write out the contents of property to the given byte array.
    use the correct word endianness when writing words of data to the array */
    pub fn copy_to_mem(&self, bytes: &mut Bytes)
    {
        match self
        {
            DeviceTreeProperty::Empty => (),
            DeviceTreeProperty::Bytes(v) => for b in v
            {
                bytes.add_u8(*b);
            },
            DeviceTreeProperty::MultipleUnsignedInt64_64(v) => for (i, j) in v
            {
                bytes.add_u64(*i);
                bytes.add_u64(*j);
            },
            DeviceTreeProperty::MultipleUnsignedInt64_32(v) => for (i, j) in v
            {
                bytes.add_u64(*i);
                bytes.add_u32(*j);
            },
            DeviceTreeProperty::MultipleUnsignedInt32_32(v) => for (i, j) in v
            {
                bytes.add_u32(*i);
                bytes.add_u32(*j);
            },
            DeviceTreeProperty::MultipleUnsignedInt64(v) => for w in v
            {
                bytes.add_u64(*w);
            },
            DeviceTreeProperty::MultipleUnsignedInt32(v)  => for w in v
            {
                bytes.add_u32(*w);
            },
            DeviceTreeProperty::UnsignedInt32(w) => bytes.add_u32(*w),
            DeviceTreeProperty::Text(s) => bytes.add_null_term_string((*s).as_str()),
            DeviceTreeProperty::MultipleText(v) => for s in v
            {
                bytes.add_null_term_string((*s).as_str());
            }
        }
    }

    /* convert array of bytes into Rust vector of whole 64-bit words */
    pub fn as_multi_u64(&self) -> Result<Vec<u64>, DeviceTreeError>
    {
        if let DeviceTreeProperty::Bytes(v) = self
        {
            let mut list = Vec::<u64>::new();
            for word in 0..(v.len() >> 3) /* divide by 8 (8 bytes in a 64-bit word) */
            {
                let i = word * size_of::<u64>();
                let int: u64 =
                    (v[i + 0] as u64) << 56 |
                    (v[i + 1] as u64) << 48 |
                    (v[i + 2] as u64) << 40 |
                    (v[i + 3] as u64) << 32 |
                    (v[i + 4] as u64) << 24 |
                    (v[i + 5] as u64) << 16 |
                    (v[i + 6] as u64) << 8  |
                    (v[i + 7] as u64) << 0;
                list.push(int);
            }
            return Ok(list);
        };
        return Err(DeviceTreeError::CannotConvert);
    }

    /* convert array of bytes into Rust vector of whole 32-bit words */
    pub fn as_multi_u32(&self) -> Result<Vec<u32>, DeviceTreeError>
    {
        if let DeviceTreeProperty::Bytes(v) = self
        {
            let mut list = Vec::<u32>::new();
            for word in 0..(v.len() >> 2) /* divide by 4 (4 bytes in a 32-bit word) */
            {
                let i = word * size_of::<u32>();
                let int: u32 = (v[i + 0] as u32) << 24 | (v[i + 1] as u32) << 16 | (v[i + 2] as u32) << 8 | (v[i + 3] as u32);
                list.push(int);
            }
            return Ok(list);
        };
        return Err(DeviceTreeError::CannotConvert);
    }

    /* return first four bytes as unsigned 32-bit integer */
    pub fn as_u32(&self) -> Result<u32, DeviceTreeError>
    {
        if let DeviceTreeProperty::Bytes(v) = self
        {
            if v.len() >= size_of::<u32>()
            {
                let int: u32 = (v[0] as u32) << 24 | (v[1] as u32) << 16 | (v[2] as u32) << 8 | (v[3] as u32);
                return Ok(int);
            }
        };
        return Err(DeviceTreeError::CannotConvert);
    }

    /* convert array of bytes, up to terminating null or end of array, into a Rust string */
    pub fn as_text(&self) -> Result<String, DeviceTreeError>
    {
        if let DeviceTreeProperty::Bytes(v) = self
        {
            let mut text = String::new();
            for c in v
            {
                if *c == 0 { break; }
                text.push(*c as char);
            }
            return Ok(text);
        };
        return Err(DeviceTreeError::CannotConvert);
    }

    /* convert multiple character arrays, split by terminating null, into a vector of Rust strings */
    pub fn as_multi_text(&self) -> Result<Vec<String>, DeviceTreeError>
    {
        if let DeviceTreeProperty::Bytes(v) = self
        {
            let mut list = Vec::<String>::new();
            let mut text = String::new();
            for c in v
            {
                if *c == 0 { break; }
                text.push(*c as char);
            }
            list.push(text);

            return Ok(list);
        }

        return Err(DeviceTreeError::CannotConvert);
    }
}

/* a node can contain child nodes that contain properties. these
properties can be in the form of (base address, size of object).
the parent node defines the bit length of these addresses and sizes 
in multiples of u32 cells */
pub struct AddressSizeCells
{
    pub address: usize, /* number of unsigned 32-bit cells to hold an address */
    pub size: usize     /* number of unsigned 32-bit cells to hold a size */
}

#[derive(PartialEq, Eq, Clone)]
enum DeviceTreeReference
{
    TotalSize,
    OffsetDTStruct,
    OffsetDTStrings,
    OffsetMemoryReservation,
    SizeDTStrings,
    SizeDTStruct,
    PropertyName(String)
}

/* parsed device tree */
pub struct DeviceTree
{
    /* store nodes in a tree, each node has a hash table of properties and values */
    nodes: BTreeMap<String, HashMap<String, DeviceTreeProperty>>,

    /* specify the boot CPU ID (or it defaults to 0) */
    boot_cpu_id: u32
}

impl DeviceTree
{
    /* create a blank structured device tree */
    pub fn new() -> DeviceTree
    {
        DeviceTree
        {
            nodes: BTreeMap::new(),
            boot_cpu_id: 0
        }
    }

    /* define the system's boot CPU ID, which defaults to 0 */
    pub fn set_boot_cpu_id(&mut self, cpu_id: u32)
    {
        self.boot_cpu_id = cpu_id;
    }

    /* add or update a property in a node. if the node doesn't exist, it's created.
       if the property doesn't exist it's added. if the property does exist, it is updated.
       => node_path = path of node to edit. this must be full and canonical
          label = label of property to edit
          value = value of property
    */
    pub fn edit_property(&mut self, node_path: &String, label: &String, value: DeviceTreeProperty)
    {
        if let Some(node) = self.nodes.get_mut(node_path)
        {
            node.insert(label.clone(), value);
        }
        else
        {
            let mut properties = HashMap::<String, DeviceTreeProperty>::new();
            properties.insert(label.clone(), value);
            self.nodes.insert(node_path.clone(), properties);
        }
    }

    /* remove a property entirely from a node
       => node_path = path of node to find. this must be full and canonical
          label = property to delete
       <= previous property value, or None for not found
    */
    pub fn delete_property(&mut self, node_path: &String, label: &String) -> Option<DeviceTreeProperty>
    {
        if let Some(node) = self.nodes.get_mut(node_path)
        {
            return node.remove(label)
        }

        None
    }

    /* get the address-cell and size-cell properties of a given node.
    if no entries can be found, use specification's defaults.
       => node_path = path of node to inspect. this must be full and canonical
       <= AddressSizeCells structure for the node
    */
    pub fn get_address_size_cells(&self, node_path: &String) -> AddressSizeCells
    {
        let mut addr_cells = DEFAULTADDRESSCELLS;
        let mut size_cells = DEFAULTSIZECELLS;

        match self.get_property(node_path, &format!("#address-cells"))
        {
            Ok(prop_value) => match prop_value.as_u32()
            {
                Ok(value) => addr_cells = value as usize,
                _ => ()
            },
            _ => ()
        };

        match self.get_property(node_path, &format!("#size-cells"))
        {
            Ok(prop_value) => match prop_value.as_u32()
            {
                Ok(value) => size_cells = value as usize,
                _ => ()
            },
            _ => ()
        };

        AddressSizeCells
        {
            address: addr_cells,
            size: size_cells
        }
    }

    /* look up the value of a property in a node
       => node_path = path of node to find. this must be full and canonical
          label = property to find
       <= property value, or None for not found
    */
    pub fn get_property(&self, node_path: &String, label: &String) -> Result<&DeviceTreeProperty, DeviceTreeError>
    {
        if let Some(node) = self.nodes.get(node_path)
        {
            if let Some(property) = node.get(label)
            {
                return Ok(property);
            }
        }

        Err(DeviceTreeError::NotFound)
    }

    /* iterate over all properties in a node
       => node_path = path of node to examine. this must be full and canonical
       <= returns iterator for the node's properties, or None if node doesn't exist.
          each iteration returns a tuple of (property name string, property value) */
    pub fn property_iter(&self, node_path: &String) -> Option<DeviceTreePropertyIter>
    {
        match self.nodes.get(node_path)
        {
            Some(node) => Some(DeviceTreePropertyIter
            {
                iter: node.iter()
            }),
            None => None
        }
    }

    /* remove a whole node from the tree. this will delete all of its properties, too.
       => node_path = path of node to delete. this must be full and canonical
    */
    pub fn delete_node(&mut self, node_path: &String)
    {
        self.nodes.remove(node_path);
    }

    /* detect that a node exists. the given path must be in full and canonical
       <= return true for exact node exists, or false for not
    */
    pub fn node_exists(&self, node_path: &String) -> bool
    {
        self.nodes.get(node_path).is_some()
    }

    /* return an iterator of all node paths matching the given path.
    note: this does greedy path matching, so searching for '/cpu' will match /cpu/cpus@0, /cpu/cpus@1, /cpu/cpus@3 etc
       => node_path_search = start of path string to match
          depth = the max number of '/' characters in the path before a match is returned. use this to
                  avoid iterating over child nodes when you just want the parent. eg, a depth of 2 for /cpu/cpus@
                  will match '/cpu/cpus@0' not '/cpu/cpus@/interrupt-controller'
       <= iterator of matching strings */
    pub fn iter(&self, node_path_search: &String, depth: DeviceTreeIterDepth) -> DeviceTreeIter
    {
        DeviceTreeIter
        {
            depth,
            to_match: node_path_search.clone(),
            iter: self.nodes.iter()
        }
    }

    /* convert device tree into a binary blob
       <= byte array containing the device tree blob, or error code */
    pub fn to_blob(&self) -> Result<Vec<u8>, DeviceTreeError>
    {
        let mut bytes = Bytes::new();
        bytes.set_ordering(Ordering::BigEndian);

        /* keep track of offsets and sizes we need to plug into the
        DTB when we're aware of the values */
        let mut references = BTreeMap::<usize, DeviceTreeReference>::new();

        /* write out metadata */
        bytes.add_u32(DTB_MAGIC);
        self.reserve_reference(&mut bytes, &mut references, DeviceTreeReference::TotalSize);
        self.reserve_reference(&mut bytes, &mut references, DeviceTreeReference::OffsetDTStruct);
        self.reserve_reference(&mut bytes, &mut references, DeviceTreeReference::OffsetDTStrings);
        self.reserve_reference(&mut bytes, &mut references, DeviceTreeReference::OffsetMemoryReservation);
        bytes.add_u32(DTB_VERSION); /* specification version */
        bytes.add_u32(LOWEST_SUPPORTED_VERSION); /* minimuum supported version */
        bytes.add_u32(self.boot_cpu_id); /* boot_cpuid_phys */
        self.reserve_reference(&mut bytes, &mut references, DeviceTreeReference::SizeDTStrings);
        self.reserve_reference(&mut bytes, &mut references, DeviceTreeReference::SizeDTStruct);

        /* create an empty reserved memory area. TODO: create a proper reserved area list */
        let pos = bytes.offset32();
        self.resolve_reference(&mut bytes, &mut references, DeviceTreeReference::OffsetMemoryReservation, pos)?;
        bytes.add_u64(0); /* reserved mem address. 0 = end list*/
        bytes.add_u64(0); /* reserved mem size. 0 = end list */

        /* keep track of the nodes we've already created in the DTB */
        let mut prev_nodes = Vec::<&str>::new();

        /* start creating nodes. the node paths should be in order when iter'ing them. essentially we
        have to turn a tree of strings (with their associated properties) like this:

        /
        /chosen
        /cpus
        /cpus/cpu@0
        /cpus/cpu@1
        /memory@....
        /uart@...
        
        into this in the DTB:

        BEGIN NODE ''
            BEGIN NODE 'chosen'
            END NODE
            BEGIN NODE 'cpus'
                BEGIN NODE 'cpu@0'
                END NODE
                BEGIN NODE 'cpu@1'
                END NODE
            END NODE
            BEGIN NODE 'memory@....'
            END NODE
            BEGIN NODE 'uart@...'
            END NODE
        END NODE

        In the case of:

        /cpus/cpu@1
        /memory@....

        We need to end the nodes of cpu@1 and cpus before creating memory@... */
        let dtstruct_start = bytes.offset32();
        self.resolve_reference(&mut bytes, &mut references, DeviceTreeReference::OffsetDTStruct, dtstruct_start)?;

        for (path, properties) in self.nodes.iter()
        {
            /* break the path string up into nodes split by the separator */
            let nodes: Vec<&str> = path.split(DEVICETREESEPARATOR).collect();

            /* loop through the nodes in the tree string. skip index 0 as it's always ''.
            eg, /chosen splits into '' and 'chosen'. */
            for index in 1..nodes.len()
            {
                /* check to see if this is a new node or one we've created before */
                match &prev_nodes.get(index)
                {
                    /* is this is a node we've not seen before in this position? */
                    Some(previous) => if **previous != nodes[index]
                    {
                        /* we're switching to a new node. close all child nodes,
                        eg if the previous nodes were: /cpus/cpu@8 and the next
                        string is /uart@1000 then close off cpu@8 then cpus before
                        creating uart@1000 */
                        loop
                        {
                            if prev_nodes.len() <= index
                            {
                                break;
                            } 
                            bytes.add_u32(FDT_END_NODE);
                            prev_nodes.pop();
                        }

                        /* write node start marker and NULL-terminated string of the node's leafname */
                        bytes.add_u32(FDT_BEGIN_NODE);
                        bytes.add_null_term_string(nodes[index]);
                        bytes.pad_to_u32();

                        prev_nodes.insert(prev_nodes.len(), nodes[index]);
                    },
                    /* no previous node in this position in the tree string so create a new node */
                    None =>
                    {
                        /* write node start marker and NULL-terminated string of the node's leafname */
                        bytes.add_u32(FDT_BEGIN_NODE);
                        bytes.add_null_term_string(nodes[index]);
                        bytes.pad_to_u32();

                        prev_nodes.insert(prev_nodes.len(), nodes[index]);
                    }
                }
            }

            /* list the proeprties for this node, reserving a 32-bit word for
            the offset into tne string of property names */
            for (name, property) in properties
            {
                let size = property.size();
                bytes.add_u32(FDT_PROP);
                bytes.add_u32(size as u32);
                self.reserve_reference(&mut bytes, &mut references,
                    DeviceTreeReference::PropertyName(name.clone()));
                property.copy_to_mem(&mut bytes);
                bytes.pad_to_u32();
            }
        }

        /* close all outstanding nodes and end the node structure */
        for _ in prev_nodes
        {
            bytes.add_u32(FDT_END_NODE);
        }
        bytes.add_u32(FDT_END);

        let dtstruct_end = bytes.offset32();
        self.resolve_reference(&mut bytes, &mut references,
            DeviceTreeReference::SizeDTStruct, dtstruct_end - dtstruct_start)?;
        
        /* resolve strings here */
        let dtstrings_start = dtstruct_end;
        self.resolve_reference(&mut bytes, &mut references,
                DeviceTreeReference::OffsetDTStrings, dtstrings_start)?;

        self.resolve_name_strings(&mut bytes, &mut references)?;

        let dtstrings_end = bytes.offset32();
        self.resolve_reference(&mut bytes, &mut references,
            DeviceTreeReference::SizeDTStrings, dtstrings_end - dtstrings_start)?;

        /* write in the final size - we're all done */
        let totalsize = bytes.len() as u32;
        self.resolve_reference(&mut bytes, &mut references,
            DeviceTreeReference::TotalSize, totalsize)?;

        Ok(bytes.as_vec())
    }

    /* reserve a 32-bit word in a byte array which will be filled with an offset to
    some other data or a size. call resolve_reference() to fill in the info.
    => bytes = Bytes array to update
       map = data structure that associates references to offsets in the bytes array
       reference = label for the information to be filled in later */
    fn reserve_reference(&self, bytes: &mut Bytes, map: &mut BTreeMap<usize, DeviceTreeReference>, reference: DeviceTreeReference)
    {
        map.insert(bytes.len(), reference);
        bytes.add_u32(0xffffffff); /* set to a wild value to see it easily in debugging */
    }

    /* find all words reserved in the byte array for the given reference and fill in the given value.
    this will remove that reference from the data structure so it cannot be resolved again.
    if an out-of-bounds write is attempted, this function will exit immediately
    with the error code OutOfBoundsWrite
    => bytes = Bytes array to update
       map = data structure that associates references to offsets in the bytes array
       to_match = label for the information to be filled in
       value = information (an offset or a size) to replace the reserved word
    <= OK if successful, or an error */
    fn resolve_reference(&self, bytes: &mut Bytes, map: &mut BTreeMap<usize, DeviceTreeReference>,
        to_match: DeviceTreeReference, value: u32) -> Result<(), DeviceTreeError>
    {
        let mut to_remove = Vec::new();

        /* yes, we have to enumerate all offsets but that's because offsets are unique
        and references may or may not. we also remove all matches so the map gets smaller
        the more resolve_reference() is called */
        for (offset, reference) in map.into_iter()
        {
            if to_match == *reference
            {
                match bytes.alter_u32(*offset, value)
                {
                    true => to_remove.push(*offset),
                    false =>  return Err(DeviceTreeError::OutOfBoundsWrite)
                }
            }
        }

        for victim in to_remove
        {
            map.remove_entry(&victim);
        }
        Ok(())
    }

    /* go through references to property names, add them to the bytes array (forming the block of name strings)
    and write the offset into the reserved word for the property's name */
    fn resolve_name_strings(&self, bytes: &mut Bytes, map: &mut BTreeMap<usize, DeviceTreeReference>) -> Result<(), DeviceTreeError>
    {
        let mut to_remove = Vec::new();
        let base = bytes.len();

        for (offset, reference) in map.into_iter()
        {
            match reference
            {
                DeviceTreeReference::PropertyName(s) =>
                {
                    let pos = bytes.len();
                    bytes.add_null_term_string(s);
                    match bytes.alter_u32(*offset, (pos - base) as u32)
                    {
                        true => to_remove.push(*offset),
                        false =>  return Err(DeviceTreeError::OutOfBoundsWrite)
                    }
                },
                _ => ()
            }
        }

        for victim in to_remove
        {
            map.remove_entry(&victim);
        }
        Ok(())
    }
}

/* iterate over all properties in a node. note the return data per iteration:
   (String, DeviceTreeProperty) where String contains the property name
   and DeviceTreeProperty contains the property value */
pub struct DeviceTreePropertyIter<'a>
{
    iter: hash_map::Iter<'a, alloc::string::String, DeviceTreeProperty>
}

impl Iterator for DeviceTreePropertyIter<'_>
{
    type Item = (String, DeviceTreeProperty);

    fn next(&mut self) -> Option<Self::Item>
    {
        match self.iter.next()
        {
            Some((s, v)) => Some((s.clone(), v.clone())),
            None => None
        }
    }
}

/* used to control the depth of the device tree search */
pub type DeviceTreeIterDepth = usize;

/* iterate over all matching node paths */
pub struct DeviceTreeIter<'a>
{
    depth: DeviceTreeIterDepth,
    to_match: String,
    iter: btree_map::Iter<'a, String, hash_map::HashMap<String, DeviceTreeProperty>>
}

impl Iterator for DeviceTreeIter<'_>
{
    type Item = String;

    fn next(&mut self) -> Option<Self::Item>
    {
        loop
        {
            if let Some((node_path, _)) = self.iter.next()
            {
                /* skip if we're out of our depth: don't go beyond self.depth number of / characters in path */
                if node_path.as_str().matches(DEVICETREESEPARATOR).count() > self.depth
                {
                    continue;
                }

                if node_path.as_str().starts_with(self.to_match.as_str()) == true
                {
                    return Some(node_path.clone());
                }
            }
            else
            {
                return None; /* end the iterator: we're out of nodes */
            }
        }
    }
}

/* allow us to inspect the device tree */
impl core::fmt::Debug for DeviceTree
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        for node in self.iter(&String::from(DEVICETREESEPARATOR), DeviceTreeIterDepth::max_value())
        {
            write!(f, "{}\n", node)?;
            if let Some(iter) = self.property_iter(&node)
            {
                for (name, value) in iter
                {
                    write!(f, " {} = {:?}\n", name, value)?;
                }
                write!(f, "\n")?;
            }
        }

        Ok(())
    }
}

/* return the parent of the given node path, going no higher than '/'.
if the path contains no '/' then, return '/' */
pub fn get_parent(path: &String) -> String
{
    if let Some(index) = path.as_str().rfind(DEVICETREESEPARATOR)
    {
        let (before, _) = path.as_str().split_at(index);
        if before.len() > 0
        {
            return String::from(before)
        }
    }

    String::from(DEVICETREESEPARATOR)
}
