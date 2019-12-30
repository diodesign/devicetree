/* Device tree blob parsing and writing
 *
 * Based on specs from: https://www.devicetree.org/specifications/ [v0.3-rc2]
 * 
 * To read a device tree blob into a parsed device tree structure, call DeviceTreeBlob::to_parsed()
 * To write a device tree structure as a device tree blob, call DeviceTree::to_blob()
 * 
 * The parsed device tree is designed to be safely iterated over, searched, cloned, and
 * modified by Rust code. Note: This code ignores empty nodes with no properties - FIXME?
 * 
 * This does not require the standard library, but it does require a heap allocator.
 * 
 * (c) Chris Williams, 2019.
 *
 * See LICENSE for usage and copying.
 */

#![no_std]
#![no_main]

#[macro_use]
extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use core::mem::{transmute};

extern crate hashbrown;
use hashbrown::hash_map::{HashMap, Iter};

const LOWEST_SUPPORTED_VERSION: u32 = 16; 

const FDT_BEGIN_NODE:   u32 = 0x00000001;
const FDT_END_NODE:     u32 = 0x00000002;
const FDT_PROP:         u32 = 0x00000003;
const FDT_NOP:          u32 = 0x00000004;
const FDT_END:          u32 = 0x00000009;

/* useful macros for rounding an address up to the next word boundaries */
macro_rules! align_to_next_u32 { ($a:expr) => ($a = ($a & !3) + 4); }
macro_rules! align_to_next_u8  { ($a:expr) => ($a = $a + 1);        }

/* returns true if address is aligned to a 32-bit word boundary */
macro_rules! is_aligned_u32    { ($a:expr) => (($a & 3) == 0);      }

/* define parsing errors / results */
#[derive(Debug)]
pub enum DeviceTreeError
{
    FailedSanityCheck,
    ReachedEnd,
    ReachedUnexpectedEnd,
    TokenUnaligned,
    SkippedToken,
    BadToken(u32)
}

/* define the header for a raw device tree blob */
#[repr(C)]
pub struct DeviceTreeBlob
{
    magic: u32,
    totalsize: u32,
    off_dt_struct: u32,
    off_dt_strings: u32,
    off_mem_rsvmap: u32,
    version: u32,
     last_comp_version: u32,
    boot_cpuid_phys: u32,
    size_dt_strings: u32,
    size_dt_struct: u32
}

impl DeviceTreeBlob
{
    /* return true if this looks like legit DTB data, or false if not */
    pub fn sanity_check(&self) -> bool
    {
        if u32::from_be(self.magic) != 0xd00dfeed || u32::from_be(self.last_comp_version) > LOWEST_SUPPORTED_VERSION
        {
            return false;
        }

        return true;
    }

    /* convert this DTB binary into a structured device tree that can be safely walked by Rust code
    <= device tree structure, or None for failure */
    pub fn to_parsed(&self) -> Result<DeviceTree, DeviceTreeError>
    {
        /* force a sanity check */
        if self.sanity_check() == false { return Err(DeviceTreeError::FailedSanityCheck); }

        let mut dt = DeviceTree::new();

        let mut offset = u32::from_be(self.off_dt_struct) as usize;
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
       <= returns entry to add to the tree, or an error/incident code
    */
    fn parse_token(&self, offset: &mut usize, current_parent_path: &mut Vec<String>) -> Result<DeviceTreeBlobTokenParsed, DeviceTreeError>
    {
        /* ensure alignment */
        if is_aligned_u32!(*offset) == false
        {
            return Err(DeviceTreeError::TokenUnaligned)
        }

        let token = match self.read_u32(*offset)
        {
            Some(t) => u32::from_be(t),
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
                let length = match self.read_u32(*offset)
                {
                    Some(l) => u32::from_be(l),
                    None => return Err(DeviceTreeError::ReachedUnexpectedEnd)
                };

                align_to_next_u32!(*offset);
                let string_offset = match self.read_u32(*offset)
                {
                    Some(so) => u32::from_be(so),
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
                            if let Some(byte) = self.read_u8(*offset)
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
                    1 => String::from("/"),
                    _ => current_parent_path.join("/")
                };

                return Ok(DeviceTreeBlobTokenParsed
                {
                    full_path: full_path,
                    property: self.get_string((string_offset + u32::from_be(self.off_dt_strings)) as usize),
                    value: value
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

    /* return the base address of the blob */
    fn get_base(&self) -> usize
    {
        unsafe { return transmute::<&DeviceTreeBlob, usize>(self) }   
    }

    /* read a 32-bit word at offset bytes from the base address of the blob
       <= value read, or None for failure */
    fn read_u32(&self, offset: usize) -> Option<u32>
    {
        if offset > u32::from_be(self.totalsize) as usize
        {
            return None; /* prevent reading beyond the end of the structure */
        }

        let addr = self.get_base() + offset;
        Some(unsafe { core::ptr::read(addr as *const u32) })
    }

    /* read a byte at offset bytes from the base address of the blob
    <= value read, or None for failure */
    fn read_u8(&self, offset: usize) -> Option<u8>
    {
        if offset > u32::from_be(self.totalsize) as usize
        {
            return None; /* prevent reading beyond the end of the structure */
        }

        let addr = self.get_base() + offset;
        Some(unsafe { core::ptr::read(addr as *const u8) })
    }

    /* return a copy of a null-terminated string at offset bytes from the base address of the blob */
    fn get_string(&self, offset: usize) -> String
    {
        let addr = self.get_base() + offset;

        let mut count = 0;
        let count_max = u32::from_be(self.totalsize) as usize; /* for bounds check */

        let mut characters = String::new();

        /* copy string one byte at a time until we hit a null byte. this assumes
        the string is using the basic ASCII defined in the specification */
        loop
        {
            match unsafe { core::ptr::read((addr + count) as *const u8) }
            {
                0 => break,
                c =>
                {
                    characters.push(c as char);

                    /* avoid running off the end of the structure */
                    align_to_next_u8!(count);
                    if count >= count_max
                    {
                        break;
                    }
                }
            };
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

/* convert the contents of a property into various formats */
#[derive(Clone, Debug)]
pub enum DeviceTreeProperty
{
    Empty,
    Bytes(Vec<u8>),
    Reg
}

impl DeviceTreeProperty
{
    // pub fn as_reg(&self) -> Vec()
}

/* parsed device tree */
pub struct DeviceTree
{
    /* store the tree in a hash table as we usually either iterate over all entries,
    or wish to find a specific entry. searching the table is not likely to be used
    in time critical cases. if this needs to be optimized, submit a patch or open
    an issue with a suggested way forward. */
    entries: HashMap<String, HashMap<String, DeviceTreeProperty>>
}

impl DeviceTree
{
    /* create a blank structured device tree */
    pub fn new() -> DeviceTree
    {
        DeviceTree
        {
            entries: HashMap::new()
        }
    }

    /* add or update a property in a node. if the node doesn't exist, it's created.
       if the property doesn't exist it's added. if the property does exist, it is updated.
       => node_path = path of node to edit. this must be full and canonical
          label = label of property to edit
          value = value of property
    */
    pub fn edit_property(&mut self, node_path: &String, label: &String, value: DeviceTreeProperty)
    {
        if let Some(node) = self.entries.get_mut(node_path)
        {
            node.insert(label.clone(), value);
        }
        else
        {
            let mut properties = HashMap::<String, DeviceTreeProperty>::new();
            properties.insert(label.clone(), value);
            self.entries.insert(node_path.clone(), properties);
        }
    }

    /* remove a property entirely from a node
       => node_path = path of node to find. this must be full and canonical
          label = property to delete
       <= previous property value, or None for not found
    */
    pub fn delete_property(&mut self, node_path: &String, label: &String) -> Option<DeviceTreeProperty>
    {
        if let Some(node) = self.entries.get_mut(node_path)
        {
            return node.remove(label)
        }

        None
    }

    /* look up the value of a property in a node
       => node_path = path of node to find. this must be full and canonical
          label = property to find
       <= property value, or None for not found
    */
    pub fn get_property(&self, node_path: &String, label: &String) -> Option<&DeviceTreeProperty>
    {
        if let Some(node) = self.entries.get(node_path)
        {
            if let Some(property) = node.get(label)
            {
                return Some(property);
            }
        }

        None
    }

    /* iterate over all properties in a node
       => node_path = path of node to examine. this must be full and canonical
       <= returns iterator for the node's properties, or None if node doesn't exist.
          each iteration returns a tuple of (property name string, property value) */
    pub fn property_iter(&self, node_path: &String) -> Option<DeviceTreePropertyIter>
    {
        match self.entries.get(node_path)
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
        self.entries.remove(node_path);
    }

    /* detect that a node exists. the given path must be in full and canonical
       <= return true for exact node exists, or false for not
    */
    pub fn node_exists(&self, node_path: &String) -> bool
    {
        self.entries.get(node_path).is_some()
    }

    /* return an iterator of all node paths matching the given path.
    note that this does greedy path matching, so searching for '/cpus' will match /cpus@0, /cpus@1, /cpus@3 etc */
    pub fn iter(&self, node_path_search: String) -> DeviceTreeIter
    {
        DeviceTreeIter
        {
            to_match: node_path_search,
            iter: self.entries.iter()
        }
    }
}

/* iterate over all properties in a node. note the return data per iteration:
   (String, DeviceTreeProperty) where String contains the property name
   and DeviceTreeProperty contains the property value */
pub struct DeviceTreePropertyIter<'a>
{
    iter: Iter<'a, alloc::string::String, DeviceTreeProperty>
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

/* iterate over all matching node paths */
pub struct DeviceTreeIter<'a>
{
    to_match: String,
    iter: Iter<'a, String, HashMap<String, DeviceTreeProperty>>
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
        for node in self.iter(String::from("/"))
        {
            write!(f, "{}\n", node);
            if let Some(iter) = self.property_iter(&node)
            {
                for (name, value) in iter
                {
                    write!(f, " {} = {:?}\n", name, value);
                }
                write!(f, "\n");
            }
        }

        Ok(())
    }
}

/* for debugging in Qemu on RISC-V */
fn debug(s: &str)
{
    for c in s.bytes()
    {
        unsafe { *(0x10000000 as *mut u8) = c };
    }
}
