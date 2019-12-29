/* Device tree blob parsing and writing
 *
 * Based on specs from: https://www.devicetree.org/specifications/ [v0.3-rc2]
 * 
 * To read a device tree blob into a parsed device tree structure, call DeviceTreeBlob::to_parsed()
 * To write a device tree structure as a device tree blob, call DeviceTree::to_blob()
 * 
 * The parsed device tree is designed to be safely iterated over, searched, cloned, and
 * modified by Rust code.
 * 
 * This does not require the standard library, but it does require a heap allocator.
 * 
 * (c) Chris Williams, 2019.
 *
 * See LICENSE for usage and copying.
 */

#![no_std]
#![no_main]

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

extern crate hashbrown;
use hashbrown::hash_map::{HashMap, Iter};

enum DeviceTreeBlobToken
{
    FDT_BEGIN_NODE  = 0x00000001,
    FDT_END_NODE    = 0x00000002,
    FDT_PROP        = 0x00000003,
    FDT_NOP         = 0x00000004,
    FDT_END         = 0x00000009
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


impl core::fmt::Debug for DeviceTreeBlob
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        write!(f, "dtb base address:    {:p}\n", self);
        write!(f, "magic:               0x{:x}\n", u32::from_be(self.magic));
        write!(f, "totalsize:           0x{:x}\n", u32::from_be(self.totalsize));
        write!(f, "off_dt_struct:       0x{:x}\n", u32::from_be(self.off_dt_struct));
        write!(f, "off_dt_strings:      0x{:x}\n", u32::from_be(self.off_dt_strings));
        write!(f, "off_mem_rsvmap:      0x{:x}\n", u32::from_be(self.off_mem_rsvmap));
        write!(f, "version:             0x{:x}\n", u32::from_be(self.version));
        write!(f, "last_comp_version:   0x{:x}\n", u32::from_be(self.last_comp_version));
        write!(f, "boot_cpuid_phys:     0x{:x}\n", u32::from_be(self.boot_cpuid_phys));
        write!(f, "size_dt_strings:     0x{:x}\n", u32::from_be(self.size_dt_strings));
        write!(f, "size_dt_struct:      0x{:x}\n", u32::from_be(self.size_dt_struct))
    }
}

impl DeviceTreeBlob
{
    /* return true if this looks like legit DTB data, or false if not */
    pub fn sanity_check(&self) -> bool
    {
        if u32::from_be(self.magic) != 0xd00dfeed
        {
            return false;
        }

        return true;
    }

    /* convert this DTB binary into a structured device tree that can be safely walked by Rust code
    <= device tree structure, or None for failure */
    pub fn to_parsed(&self) -> Option<DeviceTree>
    {
        /* force a sanity check */
        if self.sanity_check() == false
        {
            return None;
        }

        let dt = DeviceTree::new();

        Some(dt)
    }

    /* lookup a 32-bit value from a DTB string */
    fn lookup(&self, label: &str) -> Option<u32>
    {
        let addr = self.get_base() + (u32::from_be(self.off_dt_struct) as usize);
        return Some(unsafe { core::ptr::read(addr as *const u32) });
    }

    fn get_base(&self) -> usize
    {
        unsafe { return core::intrinsics::transmute::<&DeviceTreeBlob, usize>(self);  }
    }
}

#[derive(Clone)]
pub enum DeviceTreeProperty
{
    Empty,
    Unsigned32(u32),
    Unsigned64(u64),
    Text(String),
    Handle(u32),
    Array(Vec<u32>),
    Strings(Vec<String>)
}

impl core::fmt::Debug for DeviceTreeProperty
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match self
        {
            DeviceTreeProperty::Empty          => write!(f, "Empty"),
            DeviceTreeProperty::Unsigned32(v)  => write!(f, "<u32> {} (0x{:x})", v, v),
            DeviceTreeProperty::Unsigned64(v)  => write!(f, "<u64> {} (0x{:x})", v, v),
            DeviceTreeProperty::Text(s)        => write!(f, "<string> {}", s),
            DeviceTreeProperty::Handle(handle) => write!(f, "<phandle> {} (0x{:x})", handle, handle),

            DeviceTreeProperty::Array(list) =>
            {
                write!(f, "<prop-encoded-array> ");
                for i in 0..list.len()
                {
                    write!(f, "{} (0x{:x})", list[i], list[i]);
                    if i != list.len() - 1
                    {
                        write!(f, ", ");
                    }
                }
                write!(f, "")
            },

            DeviceTreeProperty::Strings(list) =>
            {
                write!(f, "<stringlist> ");
                for i in 0..list.len()
                {
                    write!(f, "'{}'", list[i]);
                    if i != list.len() - 1
                    {
                        write!(f, ", ");
                    }
                }
                write!(f, "")
            },
        }
    }
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
    pub fn edit_property(&mut self, node_path: String, label: String, value: DeviceTreeProperty)
    {
        if let Some(node) = self.entries.get_mut(&node_path)
        {
            node.insert(label, value);
        }
        else
        {
            let mut properties = HashMap::<String, DeviceTreeProperty>::new();
            properties.insert(label, value);
            self.entries.insert(node_path, properties);
        }
    }

    /* remove a property entirely from a node
       => node_path = path of node to find. this must be full and canonical
          label = property to delete
       <= previous property value, or None for not found
    */
    pub fn delete_property(&mut self, node_path: String, label: String) -> Option<DeviceTreeProperty>
    {
        if let Some(node) = self.entries.get_mut(&node_path)
        {
            return node.remove(&label)
        }

        None
    }

    /* look up the value of a property in a node
       => node_path = path of node to find. this must be full and canonical
          label = property to find
       <= property value, or None for not found
    */
    pub fn get_property(&self, node_path: String, label: String) -> Option<&DeviceTreeProperty>
    {
        if let Some(node) = self.entries.get(&node_path)
        {
            if let Some(property) = node.get(&label)
            {
                return Some(property);
            }
        }

        None
    }

    /* remove a whole node from the tree. this will delete all of its properties, too.
       => node_path = path of node to delete. this must be full and canonical
    */
    pub fn delete_node(&mut self, node_path: String)
    {
        self.entries.remove(&node_path);
    }

    /* detect that a node exists. the given path must be in full and canonical
       <= return true for exact node exists, or false for not
    */
    pub fn node_exists(&self, node_path: String) -> bool
    {
        self.entries.get(&node_path).is_some()
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
            if let Some((node_path, properties)) = self.iter.next()
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
        for (node_path, properties) in self.entries.iter()
        {
            write!(f, "{}:\n", node_path);

            for (label, property) in properties.iter()
            {
                write!(f, "--> {} = {:?}\n", label, property);
            }
        }

        write!(f, "")
    }
}