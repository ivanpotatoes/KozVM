// Read-only target snapshot exploration. No modeled API is called in the target.
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>
#include <set>
namespace Discovery {
struct Engine {
 HMODULE library=nullptr; uc_engine* uc=nullptr;
#define KVM_UC(name) decltype(&uc_##name) name=nullptr
 KVM_UC(open); KVM_UC(close); KVM_UC(mem_map); KVM_UC(mem_unmap); KVM_UC(mem_read); KVM_UC(mem_write);
 KVM_UC(reg_read); KVM_UC(reg_write); KVM_UC(hook_add); KVM_UC(emu_start); KVM_UC(emu_stop);
#undef KVM_UC
 duint base=0,size=0,allocation=0x600000000000ULL;
 std::set<duint> mapped;
 std::map<duint,std::string> apis;
 std::vector<duint> found;
 unsigned leaves=0; std::string error;
 uint64_t sectionHandle=0,sectionBase=0,sectionSize=0;
 ~Engine(){if(uc)close(uc);if(library)FreeLibrary(library);}
 bool load(){
  std::vector<wchar_t> path(32768);if(!GetModuleFileNameW(instance,path.data(),32768))return false;
  std::wstring file=path.data();file.resize(file.find_last_of(L"\\/")+1);file+=L"KozVM\\unicorn.dll";
  library=LoadLibraryExW(file.c_str(),nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
  if(!library){error="KozVM/unicorn.dll could not be loaded";return false;}
#define KVM_LOAD(name) name=reinterpret_cast<decltype(name)>(GetProcAddress(library,"uc_" #name));if(!name){error="incompatible Unicorn library";return false;}
  KVM_LOAD(open); KVM_LOAD(close); KVM_LOAD(mem_map); KVM_LOAD(mem_unmap); KVM_LOAD(mem_read); KVM_LOAD(mem_write);
  KVM_LOAD(reg_read); KVM_LOAD(reg_write); KVM_LOAD(hook_add); KVM_LOAD(emu_start); KVM_LOAD(emu_stop);
#undef KVM_LOAD
  return open(UC_ARCH_X86,UC_MODE_64,&uc)==UC_ERR_OK;
 }
 void fail(const std::string& why){if(error.empty())error=why;emu_stop(uc);}
 uint64_t reg(int id){uint64_t x=0;if(reg_read(uc,id,&x)!=UC_ERR_OK)fail("register read");return x;}
 void set(int id,uint64_t x){if(reg_write(uc,id,&x)!=UC_ERR_OK)fail("register write");}
 bool page(duint address){
  address&=~duint(4095);if(mapped.count(address))return true;
  if(mapped.size()>=32768){fail("snapshot exceeds 128 MiB");return false;}
  unsigned char data[4096]{};
  if(!DbgMemRead(address,data,sizeof(data))){fail("unreadable snapshot page "+hex(address));return false;}
  if(mem_map(uc,address,4096,UC_PROT_ALL)!=UC_ERR_OK||mem_write(uc,address,data,sizeof(data))!=UC_ERR_OK){fail("snapshot mapping");return false;}
  mapped.insert(address);return true;
 }
 bool read(duint address,void* out,size_t length){
  if(!length||address+length<address)return false;
  for(duint p=address&~duint(4095);p<address+length;p+=4096)if(!page(p))return false;
  return mem_read(uc,address,out,length)==UC_ERR_OK;
 }
 bool write(duint address,const void* data,size_t length){
  if(!length||address+length<address)return false;
  for(duint p=address&~duint(4095);p<address+length;p+=4096)if(!page(p))return false;
  return mem_write(uc,address,data,length)==UC_ERR_OK;
 }
 uint64_t qword(duint at){uint64_t x=0;if(!read(at,&x,8))fail("snapshot read "+hex(at));return x;}
 std::string string(duint at){std::string text;for(unsigned i=0;i<512;++i){char c=0;if(!read(at+i,&c,1)){fail("API string read");break;}if(!c)return text;text+=c;}fail("API string limit");return {};}
 static bool missing(uc_engine*,uc_mem_type,uint64_t address,int length,int64_t,void* data){
  auto& e=*static_cast<Engine*>(data);if(length<1||address+length<address)return false;
  for(duint p=address&~duint(4095);p<address+length;p+=4096)if(!e.page(p))return false;return true;
 }
 static void block(uc_engine*,uint64_t address,uint32_t,void* data){
  auto& e=*static_cast<Engine*>(data);if(address>=e.base&&address-e.base<e.size)return;
  auto api=e.apis.find(address);if(api==e.apis.end()){e.fail("unknown external execution "+hex(address));return;}
  const auto& name=api->second;uint64_t result=0,sp=e.reg(UC_X86_REG_RSP);
  auto a=e.reg(UC_X86_REG_RCX),b=e.reg(UC_X86_REG_RDX);
  if(name=="LocalAlloc"||name=="RtlAllocateHeap"){
   if(name=="RtlAllocateHeap")b=e.reg(UC_X86_REG_R8);
   if(!b||b>16*1024*1024){e.fail("allocation size outside model");return;}
   auto bytes=(b+4095)&~uint64_t(4095);result=e.allocation;
   if(e.mem_map(e.uc,result,bytes,UC_PROT_ALL)!=UC_ERR_OK){e.fail("emulated allocation");return;}
   for(duint p=result;p<result+bytes;p+=4096)e.mapped.insert(p);e.allocation+=bytes+4096;
  }else if(name=="NtOpenSection"||name=="ZwOpenSection"){
   auto object=e.qword(e.reg(UC_X86_REG_R8)+16);uint16_t length=0;
   if(!e.read(object,&length,2)||!length||length>1024||length%2){e.fail("section object name");return;}
   std::vector<wchar_t> path(length/2+1,0);
   if(!e.read(e.qword(object+8),path.data(),length)||_wcsicmp(path.data(),L"\\KnownDlls\\ntdll.dll")){e.fail("unsupported section name");return;}
   e.sectionHandle=0x4b564d01;result=0;
   if(!e.write(a,&e.sectionHandle,8)){e.fail("section handle output");return;}
  }else if(name=="NtMapViewOfSection"||name=="ZwMapViewOfSection"){
   if(!e.sectionHandle||a!=e.sectionHandle||b!=~uint64_t(0)){e.fail("unsupported section mapping");return;}
   auto basePtr=e.reg(UC_X86_REG_R8),sizePtr=e.qword(sp+0x38);
   auto source=M::BaseFromName("ntdll.dll"),length=M::SizeFromName("ntdll.dll");
   if(!source||!length||length>16*1024*1024||e.qword(basePtr)){e.fail("section map layout");return;}
   uint64_t destination=e.allocation,bytes=(length+4095)&~uint64_t(4095);
   if(e.mem_map(e.uc,destination,bytes,UC_PROT_ALL)!=UC_ERR_OK){e.fail("section snapshot mapping");return;}
   for(duint off=0;off<bytes;off+=4096){unsigned char page[4096]{};
    if(!e.read(source+off,page,sizeof(page))||e.mem_write(e.uc,destination+off,page,sizeof(page))!=UC_ERR_OK){e.fail("section snapshot read");return;}
    e.mapped.insert(destination+off);
   }
   e.allocation+=bytes+4096;e.sectionBase=destination;e.sectionSize=bytes;
   auto exports=e.apis;for(const auto& item:exports)if(item.first>=source&&item.first-source<length)e.apis[destination+item.first-source]=item.second;
   if(!e.write(basePtr,&destination,8)||!e.write(sizePtr,&bytes,8)){e.fail("section map output");return;}
  }else if(name=="NtUnmapViewOfSection"||name=="ZwUnmapViewOfSection"){
   if(a!=~uint64_t(0)||!e.sectionBase||b!=e.sectionBase){e.fail("unknown section view");return;}
   if(e.mem_unmap(e.uc,e.sectionBase,e.sectionSize)!=UC_ERR_OK){e.fail("section unmap");return;}
   for(duint p=e.sectionBase;p<e.sectionBase+e.sectionSize;p+=4096)e.mapped.erase(p);
   for(auto it=e.apis.begin();it!=e.apis.end();)if(it->first>=e.sectionBase&&it->first-e.sectionBase<e.sectionSize)it=e.apis.erase(it);else ++it;
   e.sectionBase=e.sectionSize=0;
  }else if(name=="NtClose"||name=="ZwClose"){
   if(!e.sectionHandle||a!=e.sectionHandle){e.fail("unknown emulated handle");return;}e.sectionHandle=0;
  }else if(name=="GetModuleHandleA")result=a?M::BaseFromName(e.string(a).c_str()):e.base;
  else if(name=="NtProtectVirtualMemory"||name=="ZwProtectVirtualMemory"){
   duint addr=e.qword(b),old=e.qword(sp+0x28);MEMORY_BASIC_INFORMATION mbi{};
   HANDLE process=OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,DbgGetProcessId());
   DWORD protection=0;if(process){if(VirtualQueryEx(process,reinterpret_cast<void*>(addr),&mbi,sizeof(mbi)))protection=mbi.Protect;CloseHandle(process);}
   if(!protection||!e.write(old,&protection,sizeof(protection))){e.fail("protection model");return;}
  }else{e.fail("unsupported startup API "+name);return;}
  auto ret=e.qword(sp);e.set(UC_X86_REG_RAX,result);e.set(UC_X86_REG_RSP,sp+8);e.set(UC_X86_REG_RIP,ret);
 }
 static int cpuid(uc_engine*,void* data){
  auto& e=*static_cast<Engine*>(data);auto pc=e.reg(UC_X86_REG_RIP);unsigned leaf=static_cast<unsigned>(e.reg(UC_X86_REG_RAX));
  unsigned bit=leaf==1?1:leaf==0x40000000?2:leaf==0x40000003?4:0;
  unsigned char native[2]{},snapshot[2]{};
  bool valid=pc>=e.base&&pc-e.base+2<=e.size&&DbgMemRead(pc,native,2)&&
   e.mem_read(e.uc,pc,snapshot,2)==UC_ERR_OK&&native[0]==0x0f&&native[1]==0xa2&&memcmp(native,snapshot,2)==0;
  // 3.8 and later scatter the output stores across calls and indexed handlers. Validate
  // actual emulated execution and the ordered leaf path rather than a contiguous body.
  if(profiles[selected].id>=380){
   BASIC_INSTRUCTION_INFO ins{};DbgDisasmFastAt(pc,&ins);
   valid=valid&&ins.size==2&&bit==(e.leaves==0?1u:e.leaves==1?2u:e.leaves==3?4u:0u);
  }else valid=valid&&handler(pc);
  if(!bit||!valid){e.fail("unexpected CPUID path");return 1;}
  if(std::find(e.found.begin(),e.found.end(),pc)==e.found.end())e.found.push_back(pc);
  if(e.found.size()>3){e.fail("more than three CPUID sites");return 1;}
  int raw[4]{};__cpuidex(raw,static_cast<int>(leaf),static_cast<int>(e.reg(UC_X86_REG_RCX)));
  if(leaf==1)raw[2]|=static_cast<int>(0x80000000u);
  else if(leaf==0x40000000){raw[0]=std::max(raw[0],0x40000003);raw[1]=0x7263694d;raw[2]=0x666f736f;raw[3]=0x76482074;}
  else raw[1]|=1;
  const int regs[]={UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX};
  for(unsigned i=0;i<4;++i)e.set(regs[i],static_cast<unsigned>(raw[i]));
  e.leaves|=bit;if(e.leaves==7)e.emu_stop(e.uc);return 1;
 }
 bool run(std::vector<duint>& output){
  if(!load())return false;base=M::GetMainModuleBase();size=M::GetMainModuleSize();
  if(!base||!size||size>128*1024*1024){error="image size outside discovery limit";return false;}
  for(duint p=base;p<base+size;p+=4096)if(!page(p))return false;
  const R::RegisterEnum live[]={R::RAX,R::RBX,R::RCX,R::RDX,R::RSI,R::RDI,R::RBP,R::RSP,R::R8,R::R9,R::R10,R::R11,R::R12,R::R13,R::R14,R::R15,R::RIP};
  const int emu[]={UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_RBP,UC_X86_REG_RSP,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15,UC_X86_REG_RIP};
  for(unsigned i=0;i<sizeof(live)/sizeof(live[0]);++i)set(emu[i],R::Get(live[i]));
  set(UC_X86_REG_EFLAGS,R::Get(R::CFLAGS)&~duint(0x10100));set(UC_X86_REG_GS_BASE,DbgGetTebAddress(DbgGetThreadId()));
  for(const char* lib:{"kernel32","kernelbase","ntdll"})for(const char* name:{"LocalAlloc","RtlAllocateHeap","NtOpenSection","ZwOpenSection","NtMapViewOfSection","ZwMapViewOfSection","NtUnmapViewOfSection","ZwUnmapViewOfSection","NtClose","ZwClose","GetModuleHandleA","NtProtectVirtualMemory","ZwProtectVirtualMemory"}){
   auto address=DbgValFromString((std::string(lib)+"."+name).c_str());if(address)apis[address]=name;
  }
  uc_hook h1=0,h2=0,h3=0,h4=0;
  if(hook_add(uc,&h1,UC_HOOK_MEM_UNMAPPED,reinterpret_cast<void*>(missing),this,1,0)!=UC_ERR_OK||
     hook_add(uc,&h2,UC_HOOK_BLOCK,reinterpret_cast<void*>(block),this,0,base-1)!=UC_ERR_OK||
     hook_add(uc,&h4,UC_HOOK_BLOCK,reinterpret_cast<void*>(block),this,base+size,UINT64_MAX)!=UC_ERR_OK||
     hook_add(uc,&h3,UC_HOOK_INSN,reinterpret_cast<void*>(cpuid),this,1,0,UC_X86_INS_CPUID)!=UC_ERR_OK){error="emulator hooks";return false;}
  auto result=emu_start(uc,R::GetCIP(),0,profiles[selected].id==3101?60000000:profiles[selected].id>=380?30000000:15000000,profiles[selected].id==3101?1000000000:profiles[selected].id>=380?300000000:100000000);
  if(result!=UC_ERR_OK||leaves!=7||!error.empty()){if(error.empty())error="discovery budget/error "+std::to_string(result)+" at "+hex(reg(UC_X86_REG_RIP))+" leaves="+std::to_string(leaves);return false;}
  output=found;return true;
 }
};
}

