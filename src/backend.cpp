#include "backend.h"
#include <windows.h>
#include <intrin.h>
#include <_plugins.h>
#include <_scriptapi_register.h>
#include <_scriptapi_module.h>
#include <vector>
#include <map>
#include <string>
#include <mutex>
#include <algorithm>
#include <cstdint>
#include <cstring>

namespace Backend {
namespace R=Script::Register;
namespace M=Script::Module;
static std::recursive_mutex gate;
static int profileId=331;
static bool armed=false;
static uint64_t leaf1Hits=0,vendorHits=0,privilegeHits=0;
struct Owned {duint pc;std::string name,command;BPXTYPE kind=bp_memory;};
static std::vector<Owned> owned;
static std::vector<duint> sites;
static std::map<duint,unsigned> hot;
static void log(const char* s){_plugin_logprintf("[KozVM] %s\n",s);}
static std::string hex(duint x){char b[32];sprintf_s(b,"%llX",static_cast<unsigned long long>(x));return b;}
static bool cmd(const std::string& s){return DbgCmdExecDirect(s.c_str());}
static bool same(const Owned& o){BRIDGEBP b{};return DbgFunctions()->GetBridgeBp(o.kind,o.pc,&b)&&b.addr==o.pc&&o.name==b.name&&o.command==b.commandText;}
static bool disarm(bool stopping=false){
 if(!stopping&&DbgIsDebugging()&&DbgIsRunning()){log("Pause the target before changing the profile.");return false;}
 bool ok=true;
 for(auto it=owned.begin();it!=owned.end();){
  if(!DbgIsDebugging()||DbgGetBpxTypeAt(it->pc)==bp_none){it=owned.erase(it);continue;}
  if(!same(*it)){log("Owned breakpoint was changed externally; leaving it untouched. Restore/remove it before retrying.");ok=false;++it;continue;}
  if(!cmd(std::string(it->kind==bp_memory?"bpmc ":"bphwc ")+hex(it->pc))){ok=false;++it;continue;}
  it=owned.erase(it);
 }
 if(ok){armed=false;sites.clear();}
 return ok;
}
static bool add(duint pc){
 Owned o{pc,"KVM_"+hex(pc),"kvm_hit"};
 if(!cmd("bpmrange "+hex(pc)+",1000,x"))return false;
 BRIDGEBP b{};
 if(!DbgFunctions()->GetBridgeBp(bp_memory,pc,&b)||b.addr!=pc)return false;
 if(!cmd("SetMemoryBreakpointName "+hex(pc)+",\""+o.name+"\"")){cmd("bpmc "+hex(pc));return false;}
 owned.push_back(o);
 bool ok=cmd("SetMemoryBreakpointCommand "+hex(pc)+",\""+o.command+"\"");
 if(!ok){cmd("bpmc "+hex(pc));owned.pop_back();return false;}
 ok=cmd("SetMemoryBreakpointCondition "+hex(pc)+",0")&&cmd("SetMemoryBreakpointFastResume "+hex(pc)+",0")&&cmd("SetMemoryBreakpointCommandCondition "+hex(pc)+",1")&&cmd("SetMemoryBreakpointSilent "+hex(pc)+",1");
 return ok&&DbgFunctions()->GetBridgeBp(bp_memory,pc,&b)&&b.enabled&&o.name==b.name&&o.command==b.commandText&&!b.fastResume&&b.silent&&strcmp(b.breakCondition,"0")==0&&strcmp(b.commandCondition,"1")==0;
}
// Follow a bounded native CPUID handler, including direct jump splits.
// Require the stack adjustment and all four output stores to one base.
static bool handler(duint pc){
 unsigned char op[2]{};if(!DbgMemRead(pc,op,2)||op[0]!=0x0f||op[1]!=0xa2)return false;
 const duint image=M::GetMainModuleBase(),imageSize=M::GetMainModuleSize();
 duint cursor=pc+2;unsigned base=16,found=0,jumps=0;std::vector<duint> visited;
 for(unsigned n=0;n<64;++n){
  if(cursor<image||cursor-image>=imageSize||std::find(visited.begin(),visited.end(),cursor)!=visited.end())return false;
  visited.push_back(cursor);unsigned char bytes[16]{};if(!DbgMemRead(cursor,bytes,sizeof(bytes)))return false;
  BASIC_INSTRUCTION_INFO d{};DbgDisasmFastAt(cursor,&d);
  if(d.size<=0||d.size>15||strncmp(d.instruction,"ret",3)==0)return false;
  if(d.branch){
   if(++jumps>4)return false;
   if(bytes[0]==0xe9){int32_t rel;memcpy(&rel,bytes+1,4);cursor=cursor+5+rel;continue;}
   if(bytes[0]==0xeb){cursor=cursor+2+static_cast<int8_t>(bytes[1]);continue;}
   return false;
  }
  if((bytes[0]==0x48||bytes[0]==0x49)&&bytes[1]==0x81&&(bytes[2]&0xf8)==0xe8&&bytes[3]==12&&!bytes[4]&&!bytes[5]&&!bytes[6]){
   if(base!=16)return false;base=(bytes[2]&7u)+((bytes[0]&1u)?8u:0u);
  }
  size_t pos=0;unsigned rex=0;if((bytes[pos]&0xf0)==0x40)rex=bytes[pos++];
  if(base!=16&&bytes[pos]==0x89&&!(rex&12u)){
   unsigned m=bytes[pos+1],mode=m>>6,reg=(m>>3)&7u,low=m&7u;size_t offset=pos+2;
   bool simple=mode!=3;
   if(low==4){unsigned sib=bytes[offset++];simple=simple&&((sib>>3)&7u)==4&&!(rex&2u);low=sib&7u;}
   unsigned rm=low+((rex&1u)?8u:0u);
   if(mode==0&&low==5)simple=false;
   if(simple&&rm==base&&reg<4){
    int32_t disp=0;if(mode==1)disp=static_cast<signed char>(bytes[offset]);else if(mode==2)memcpy(&disp,bytes+offset,4);
    int want=reg==0?12:reg==3?8:reg==1?4:0;
    if(disp==want)found|=1u<<reg;
   }
  }
  if(found==15)return true;cursor+=static_cast<duint>(d.size);
 }
 return false;
}
static bool scan(std::vector<duint>& result){
 duint base=M::GetMainModuleBase(),size=M::GetMainModuleSize();IMAGE_DOS_HEADER dos{};
 if(!base||!DbgMemRead(base,&dos,sizeof(dos))||dos.e_magic!=IMAGE_DOS_SIGNATURE||dos.e_lfanew<0)return false;
 IMAGE_NT_HEADERS64 nt{};if(static_cast<duint>(dos.e_lfanew)>size||!DbgMemRead(base+dos.e_lfanew,&nt,sizeof(nt))||nt.Signature!=IMAGE_NT_SIGNATURE||nt.FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64||nt.FileHeader.NumberOfSections>96)return false;
 duint sh=base+dos.e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+nt.FileHeader.SizeOfOptionalHeader;
 for(unsigned n=0;n<nt.FileHeader.NumberOfSections;++n){
  IMAGE_SECTION_HEADER sec{};if(!DbgMemRead(sh+n*sizeof(sec),&sec,sizeof(sec)))return false;
  if(!(sec.Characteristics&IMAGE_SCN_MEM_EXECUTE))continue;
  duint begin=sec.VirtualAddress,length=sec.Misc.VirtualSize;
  if(begin>size||length>size-begin)return false;
  for(duint off=0;off<length;off+=4096){
   unsigned char buf[4097]{};duint len=std::min<duint>(sizeof(buf),length-off);
   if(!DbgMemRead(base+begin+off,buf,len)){log("An executable page could not be read; refusing incomplete setup.");return false;}
   for(duint j=0;j+1<len&&j<4096;++j)if(buf[j]==0x0f&&buf[j+1]==0xa2&&handler(base+begin+off+j)){
    result.push_back(base+begin+off+j);if(result.size()>256u){log("Too many candidates; refusing this layout.");return false;}
   }
  }
 }
 return !result.empty();
}
bool apply(int id,bool enabled,bool cpuid){std::lock_guard<std::recursive_mutex> lock(gate);
 if(!DbgIsDebugging()||DbgIsRunning()){log("Load and pause an x64 target first.");return false;}
 if(!disarm())return false;if(!enabled||!cpuid){log("CPUID handling disabled.");return true;}
 if(!available(id)){log("Backend not published for this profile.");return false;}profileId=id;
 std::vector<duint> candidates;
 if(!scan(candidates)){log("No supported CPUID handler layout, or scan failed. Profile not armed.");return false;}
 BPMAP existing{};DbgGetBpList(bp_memory,&existing);
 bool conflict=false;for(int i=0;i<existing.count;++i)for(auto pc:candidates)if((existing.bp[i].addr&~duint(4095))==(pc&~duint(4095)))conflict=true;
 if(existing.bp)BridgeFree(existing.bp);
 if(conflict){log("Existing memory breakpoint page conflict; setup aborted.");return false;}
 std::vector<duint> pages;for(auto pc:candidates){auto page=pc&~duint(4095);if(std::find(pages.begin(),pages.end(),page)==pages.end())pages.push_back(page);}
 for(auto pc:pages)if(!add(pc)){log("Memory breakpoint setup failed; rolling back.");disarm();return false;}
 sites=std::move(candidates);hot.clear();leaf1Hits=vendorHits=privilegeHits=0;armed=true;
 char message[160];sprintf_s(message,"Profile %d armed: %u CPUID candidates; code bytes unchanged.",profileId,static_cast<unsigned>(sites.size()));log(message);return true;
}
static void accelerate(duint pc){
 duint page=pc&~duint(4095);
 auto mem=std::find_if(owned.begin(),owned.end(),[&](const Owned& o){return o.kind==bp_memory&&o.pc==page;});
 const unsigned threshold=8192u;
 if(mem==owned.end())return;
 unsigned visits=++hot[page];
 if(visits!=threshold)return;
 Owned guard=*mem;
 BPMAP map{};DbgGetBpList(bp_hardware,&map);unsigned used=0;
 for(int i=0;i<map.count;++i)if(map.bp[i].slot<4)used|=1u<<map.bp[i].slot;
 if(map.bp)BridgeFree(map.bp);
 auto dr7=R::Get(R::DR7);for(unsigned i=0;i<4;++i)if((dr7>>(i*2))&3u)used|=1u<<i;
 unsigned free=0;for(unsigned i=0;i<4;++i)if(!(used&(1u<<i)))++free;
 std::vector<duint> targets;for(auto x:sites)if((x&~duint(4095))==page)targets.push_back(x);
 if(targets.empty()||targets.size()>4)return;
 if(targets.size()>free)return;
 std::vector<Owned> added;
 for(auto x:targets){
  Owned o{x,"KVM_HW_"+hex(x),"kvm_hit",bp_hardware};
  if(!cmd("bphws "+hex(x)+",x,1"))break;
  bool ok=cmd("SetHardwareBreakpointName "+hex(x)+",\""+o.name+"\"")&&cmd("SetHardwareBreakpointCommand "+hex(x)+",kvm_hit")&&cmd("SetHardwareBreakpointCondition "+hex(x)+",0")&&cmd("SetHardwareBreakpointCommandCondition "+hex(x)+",1")&&cmd("SetHardwareBreakpointFastResume "+hex(x)+",0")&&cmd("SetHardwareBreakpointSilent "+hex(x)+",1");
  if(!ok||!same(o)){cmd("bphwc "+hex(x));break;}
  added.push_back(o);
 }
 if(added.size()!=targets.size()){for(auto& o:added)cmd("bphwc "+hex(o.pc));return;}
 if(!same(guard)||!cmd("bpmc "+hex(page))){for(auto& o:added)cmd("bphwc "+hex(o.pc));return;}
 owned.erase(std::remove_if(owned.begin(),owned.end(),[&](const Owned& o){return o.kind==bp_memory&&o.pc==page;}),owned.end());
 owned.insert(owned.end(),added.begin(),added.end());log("Hot guard page moved to free hardware slots.");
}
bool hit(int,char**){std::lock_guard<std::recursive_mutex> lock(gate);
 duint pc=R::GetCIP();
 if(!armed)return false;
 accelerate(pc);if(std::find(sites.begin(),sites.end(),pc)==sites.end())return true;
 unsigned char opcode[2]{};if(!DbgMemRead(pc,opcode,2)||opcode[0]!=0x0f||opcode[1]!=0xa2){log("CPUID candidate changed; leaving execution untouched.");return true;}
 unsigned leaf=R::GetEAX();
 if(leaf!=1&&leaf!=0x40000000&&leaf!=0x40000003)return true;
 int raw[4]{};__cpuidex(raw,static_cast<int>(leaf),static_cast<int>(R::GetECX()));
 unsigned a=static_cast<unsigned>(raw[0]),b=static_cast<unsigned>(raw[1]),c=static_cast<unsigned>(raw[2]),d=static_cast<unsigned>(raw[3]);
 if(leaf==1){c|=0x80000000u;++leaf1Hits;}
 else if(leaf==0x40000000){a=std::max(a,0x40000003u);b=0x7263694d;c=0x666f736f;d=0x76482074;++vendorHits;}
 else{b|=1u;++privilegeHits;}
 bool ok=R::SetEAX(a)&&R::SetEBX(b)&&R::SetECX(c)&&R::SetEDX(d)&&R::SetCIP(pc+2);
 if(!ok){log("CPUID emulation failed; stopping.");DbgCmdExec("pause");}
 else {char text[128];sprintf_s(text,"CPUID leaf %08X handled at %llX",leaf,static_cast<unsigned long long>(pc));log(text);
  if(leaf==0x40000003&&leaf1Hits&&vendorHits){
   bool clean=true;for(auto it=owned.begin();it!=owned.end();){if(same(*it)&&cmd(std::string(it->kind==bp_memory?"bpmc ":"bphwc ")+hex(it->pc)))it=owned.erase(it);else{clean=false;++it;}}
   if(clean){armed=false;sites.clear();char message[128];sprintf_s(message,"Profile %d accepted CPUID path complete; all KozVM guards removed.",profileId);log(message);}else log("Guard cleanup failed; pause and inspect before continuing.");
  }
 }
 return ok;
}
void cleanSavedBreakpoints(){
 std::lock_guard<std::recursive_mutex> lock(gate);
 for(auto kind:{bp_memory,bp_hardware}){
  BPMAP map{};DbgGetBpList(kind,&map);std::vector<duint> stale;
  for(int i=0;i<map.count;++i){auto& b=map.bp[i];
   if(strncmp(b.name,"KVM_",4)==0&&strcmp(b.commandText,"kvm_hit")==0&&strcmp(b.breakCondition,"0")==0&&strcmp(b.commandCondition,"1")==0&&b.silent&&!b.fastResume)stale.push_back(b.addr);
  }
  if(map.bp)BridgeFree(map.bp);
  for(auto pc:stale)if(!cmd(std::string(kind==bp_memory?"bpmc ":"bphwc ")+hex(pc)))log("Could not remove a saved KozVM breakpoint.");
 }
}

bool available(int id){return id==331||id==340||id==350;}
bool stop(bool stopping){std::lock_guard<std::recursive_mutex> lock(gate);return disarm(stopping);}
void reset(){std::lock_guard<std::recursive_mutex> lock(gate);armed=false;sites.clear();owned.clear();hot.clear();leaf1Hits=vendorHits=privilegeHits=0;}
bool status(int,char**){std::lock_guard<std::recursive_mutex> lock(gate);_plugin_logprintf("[KozVM] profile=%d armed=%u handlers=%u leaf1=%llu vendor=%llu privilege=%llu\n",profileId,armed,static_cast<unsigned>(sites.size()),leaf1Hits,vendorHits,privilegeHits);return true;}
}
