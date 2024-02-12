from binaryninja.binaryview import BinaryView, ReferenceSource
from binaryninja.types import Type
from binaryninja import log_info, log_warn, PluginCommand
from binaryninja.highlevelil import HighLevelILCall, HighLevelILConstPtr, HighLevelILVar, HighLevelILAddressOf
from binaryninja.enums import SectionSemantics
import uuid
from typing import Iterator, Set

class PrefixTrie:
    def __init__(self):
        self.root = {}

    def insert(self, byte_array: bytes, value: str) -> None:
        node = self.root
        for byte in byte_array:
            if byte not in node:
                node[byte] = {}
            node = node[byte]
        node['value'] = value

    def search(self, byte_array: bytes) -> Iterator[tuple[int, str]]:
        for start_index in range(len(byte_array)):
            node = self.root
            for i in range(start_index, len(byte_array)):
                byte = byte_array[i]
                if byte in node:
                    node = node[byte]
                    if 'value' in node:
                        yield (start_index, node['value'])
                else:
                    break

    @classmethod
    def build_trie_from_bv(cls, bv: BinaryView) -> 'PrefixTrie':
        trie = cls()
        tl = bv.get_type_library(bv.platform.name)
        types = tl.query_metadata("type_guids")
        types.update(tl.query_metadata("com_instance_names"))
        for guid, name in types.items():
            if guid != 'None':
                try:
                    byte_array = uuid.UUID(guid).bytes_le
                    # ensure byte array is not just all 0s
                    if any(byte_array):
                        trie.insert(byte_array, name)
                except:
                    log_warn(f"Failed to parse guid {repr(guid)}, {name}")
                    pass
        return trie

def get_callers_of_address(bv: BinaryView, address: int) -> Iterator[ReferenceSource]:
    for ref in bv.get_code_refs(address):
        if ref.function is None:
            continue
        if ref.function.is_thunk:
            yield from get_callers_of_address(bv, ref.function.start)
        else:
            yield ref

def get_callers_of_symbol(bv: BinaryView, symbol_name: str) -> Set[HighLevelILCall]:
    def traverser(i):
        if isinstance(i, HighLevelILCall):
            return i
        return None
    if sym := bv.get_symbol_by_raw_name(symbol_name):
        unique_refs = set()
        for ref in get_callers_of_address(bv, sym.address):
            hlil = ref.hlil
            if hlil is None:
                continue
            if il := hlil.traverse(traverser):
                unique_refs.add(il)
        return unique_refs
    return set()

def main(bv: BinaryView):
    # Step 1: Construct a trie of all known GUIDs and search for them in the binary
    #         For each of them, define a GUID at that location allowing the DataRenderer
    #         to display them nicely
    platform = bv.platform
    if platform is None or not platform.name.startswith("windows-x86"):
        log_warn("COMpanion: Only supports windows usermode platforms")
        return
    bv.begin_undo_actions()
    count = 0
    trie = PrefixTrie.build_trie_from_bv(bv)
    guid_sites = {}
    guid_type = platform.get_type_by_name("GUID")
    assert guid_type is not None, "GUID type not found"
    for sec in bv.sections.values():
        if sec.semantics != SectionSemantics.ReadOnlyDataSectionSemantics:
            continue
        file_bytes = bv.read(sec.start, sec.length)
        for start, name in trie.search(file_bytes):
            bv.define_user_data_var(sec.start + start, guid_type, f"GUID({name})")
            guid_sites[sec.start + start] = (name, bv.read(sec.start + start, 16))
            count += 1

    # Step 2: Find all calls to CoCreateInstance/CoGetClassObject and import the type for the GUID's referenced,
    #         set the type to the last parameter to this type and rename the variable.
    # TODO: This needs to be refactored so that you can specify which parameter the GUID is in and which the out parameter is in
    #       Fortunately all of the below have the GUID in the second to last param and the out class in the last param
    callers = (get_callers_of_symbol(bv, "CoCreateInstance") |
        get_callers_of_symbol(bv, "CoGetClassObject") |
        get_callers_of_symbol(bv, "AccessibleObjectFromWindow") |
        get_callers_of_symbol(bv, "CreateStdAccessibleObject"))
    for hlil in callers:
        log_info(f"CoCreateInstance/CoGetClassObject call at {hlil.address:x} {hlil}")
        # Check if the -2 parameter is a DataVariable guid
        if len(hlil.params) < 2:
            continue

        if not isinstance(hlil.params[-2], HighLevelILConstPtr) or hlil.params[-2].constant not in guid_sites:
            continue

        type_name, guid_bytes = guid_sites[hlil.params[-2].constant]
        type = bv.import_type_by_guid(uuid.UUID(bytes_le=guid_bytes))
        if type is None:
            continue
        # Check if the last parameter is a simple variable that we can apply a type to
        def var_for_param(i):
            match (i):
                case HighLevelILAddressOf(src=HighLevelILVar()):
                    return (i.src.var, 1)
                case HighLevelILVar():
                    return (i.var, 2)
                case _:
                    return None
        if var := var_for_param(hlil.params[-1]):
            var, indirection = var
            target_type = type
            for _ in range(indirection):
                target_type = Type.pointer(platform.arch, target_type)
            var.set_name_and_type_async(f"{'p'*indirection}{type_name}", target_type)
    bv.commit_undo_actions()
    bv.update_analysis()
    log_info(f"Done: {count} guids found")

PluginCommand.register("COMpanion - Apply Types", "COM Reverse engineering helper", main)
