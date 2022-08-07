/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package solanaloader;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.cmd.function.SetFunctionNameCmd;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.cmd.function.*;
public class SolanaLoaderLoader extends AbstractLibrarySupportLoader {

	private ElfHeader elfHeader;

	@Override
	public String getName() {
		return "Solana eBPF ELF Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		try {
			elfHeader = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, provider);

			elfHeader.parse();

			System.out.println("Elf machine");
			System.out.println(elfHeader.e_machine());

			// Check machine type
			if (elfHeader.e_machine() != 247) {
				System.out.println("Wrong machine for Solana Loader");
				return loadSpecs;
			}

			//
			for (ElfSectionHeader sectionHeader : elfHeader.getSections()) {
				System.out.println("Section:");
				System.out.println(sectionHeader.getNameAsString());
				System.out.println(sectionHeader.getName());
			}

			// Get .rel.dyn section:
			ElfSectionHeader relDynSectionHeader = elfHeader.getSection(".rel.dyn");
			// Get relocation table
			ElfRelocationTable relDynTable = elfHeader.getRelocationTable(relDynSectionHeader);

			System.out.println("relDynTable");
			System.out.println(relDynTable);

			ElfSymbolTable symTable = relDynTable.getAssociatedSymbolTable();
			ElfSymbol[] symbols = symTable.getSymbols();
			for (ElfRelocation relocation : relDynTable.getRelocations()) {
				System.out.println("Relocation");
				System.out.println(relocation.getOffset());
				int symbolIndex = relocation.getSymbolIndex();
				System.out.println("  Sym:" + symbols[symbolIndex].toString());
			}

			ElfSectionHeader textSectionHeader = elfHeader.getSection(".text");

			System.out.println(elfHeader.getSections());
		} catch (ElfException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

//		
//		// TODO: Examine the bytes in 'provider' to determine if this loader can load it.  If it 
//		// can load it, return the appropriate load specifications.
		loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("eBPF:LE:64:default", "default"), true));

		return loadSpecs;
	}

	

	private void createPreparedFunction(FlatProgramAPI api, Program program, Address addr, String function_name) {
		if(function_name.equals("sol_log_")) {
			
			System.out.println("CREATE SOLLOG");
			FunctionSignatureParser parser = new FunctionSignatureParser(program.getDataTypeManager(), null);
			try {
				FunctionDefinition definition = parser.parse(null, "void sol_log_(char *, ulong)");

				ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(addr, definition, SourceType.ANALYSIS);
				cmd.applyTo(program);
			} catch (CancelledException e) {
				System.out.println("CancelledException");
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ParseException e) {
				System.out.println("ParseException");
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		}
		

	
	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {

		// TODO: Load the bytes from 'provider' into the 'program'.
		
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		InputStream inStream = provider.getInputStream(0);
		Memory mem = program.getMemory();

		System.out.println("Loader");
		try {
			
			ElfSectionHeader textSectionHeader = elfHeader.getSection(".text");
			long textOffset = textSectionHeader.getOffset();
			
			
			Address programBase = api.toAddr("0x100000000");
			InputStream ELFStream = provider.getInputStream(0);
			mem.createInitializedBlock("ELF", api.toAddr(0x0), ELFStream, ELFStream.available(), monitor, false);

			mem.createInitializedBlock("program", api.toAddr("0x100000000"), textSectionHeader.getDataStream(),
					textSectionHeader.getSize(), monitor, false);
			
			mem.createUninitializedBlock("stack", api.toAddr("0x200000000"), 4096, false);
			mem.createUninitializedBlock("heap", api.toAddr("0x300000000"), 32 * 1024, false);
			
			mem.createInitializedBlock("solana_funcs",  api.toAddr("0x010000000"), 32*1024, (byte) 0, monitor, false);
			
			// Get .rel.dyn section:
			ElfSectionHeader relDynSectionHeader = elfHeader.getSection(".rel.dyn");
			// Get relocation table
			ElfRelocationTable relDynTable = elfHeader.getRelocationTable(relDynSectionHeader);

			System.out.println("relDynTable");
			System.out.println(relDynTable);

			
			ElfSymbolTable symTable = relDynTable.getAssociatedSymbolTable();
			ElfSymbol[] symbols = symTable.getSymbols();
			long label_offset = 0;
			Address fakeFuncBase = api.toAddr("0x010000000");
			HashMap<String, Address> symbolCache = new HashMap<String, Address>();
			

			
			
			
			Address entrypoint = api.toAddr("0x100000000").add(elfHeader.e_entry() - textOffset);
			Function f = api.createFunction(entrypoint, "_entry");
			api.addEntryPoint(entrypoint);
			api.disassemble(api.toAddr("0x100000000"));
			api.disassemble(entrypoint);
			
			
			// Fixup relative calls ...
			Address faddress = api.toAddr("0x100000000");
			// TODO: This fails horrible if we get a modified ELF :)
			long instruction_count = textSectionHeader.getSize() / 8;
			
			for(long i = 0; i < instruction_count; i++) {
				Instruction ins = api.getInstructionAt(faddress);
				if(ins == null) {
					api.disassemble(faddress);
				}
				
				ins = api.getInstructionAt(faddress);
				if(ins == null) {
					System.out.println("SHOULD NEVER HAPPEN!!!");
					System.out.println(faddress);
					faddress = faddress.add(8);
					continue;
				}
				
				if(!ins.getMnemonicString().equals("CALL")){
					faddress = faddress.add(8);
					continue;
				}
				
				if(ins.getInt(4) == -1) {
					System.out.println("IS SYSCALL");
					faddress = faddress.add(8);
					continue;
					
				}
				
				System.out.println("CALLIMM: ");
				System.out.println(ins.getInt(4));
				Address targetAddr = faddress.add((ins.getInt(4) * 8) + 8);
				Reference[] references = ins.getOperandReferences(0);
				for (Reference ref : references) {
					ins.removeOperandReference(0,  ref.getToAddress());
				}
				
				ins.addOperandReference(0, targetAddr, RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS);
				
				faddress = faddress.add(8);
			}
			
			
			
			for (ElfRelocation relocation : relDynTable.getRelocations()) {
				int symbolIndex = relocation.getSymbolIndex();
				String symbolName = symbols[symbolIndex].getNameAsString();
				
				// Not sure why there is an empty symbol at the beginning. 
				// Currently we just ignore it.
				if(symbolName == "") {
					continue;
				}
				long offsetInProgram = relocation.getOffset() - textOffset;
				
				
				if(!symbolCache.containsKey(symbolName)) {					
					Address address = fakeFuncBase.add(label_offset);
					
					try {
						api.createLabel(address, symbolName, true);
						api.createFunction(address, symbolName);
					} catch (AddressOutOfBoundsException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					symbolCache.put(symbolName, address);
					
					createPreparedFunction(api, program, address, symbolName);
					
					label_offset += 4;
				}
				
				Address symAddress = symbolCache.get(symbolName);
				Address progAddress = programBase.add(offsetInProgram);

				api.disassemble(progAddress);
				Instruction ins = api.getInstructionAt(progAddress);
				if(ins == null) {
					System.out.println("NO INSTRUCTION AT ADDRESS!");
					System.out.println(progAddress);
					continue;
				}
				ins.removeExternalReference(0);
				Reference[] references = ins.getOperandReferences(0);
				for (Reference ref : references) {
					ins.removeOperandReference(0,  ref.getToAddress());
				}
				
				ins.addOperandReference(0, symAddress, RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS);
			}
		} catch (LockException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MemoryConflictException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (AddressOverflowException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MemoryAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 

	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here. Not all options
		// require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
