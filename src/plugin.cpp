#include <windows.h>
#include <intrin.h>
#include <commctrl.h>
#include <_plugins.h>
#include <_scriptapi_register.h>
#include <_scriptapi_module.h>
#include <vector>
#include <map>
#include <string>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <cstdint>
#include <cstring>
namespace R=Script::Register;
namespace M=Script::Module;
static HINSTANCE instance;
static HWND owner,dialogWindow;
static int handle;
static std::wstring ini;
static std::recursive_mutex gate;
static bool enabled=true,autoArm=true,armed=false,menuReady=false;
struct Profile {int id,menu;const char* command;const char* label;const wchar_t* wide;};
static const Profile profiles[]={
 {331,1,"kvm_profile 331","VMProtect 3.3.1 - x64",L"VMProtect 3.3.1 - x64"},
 {340,7,"kvm_profile 340","VMProtect 3.4.0 - x64",L"VMProtect 3.4.0 - x64"},
 {350,8,"kvm_profile 350","VMProtect 3.5.0 - x64",L"VMProtect 3.5.0 - x64"},
 {360,9,"kvm_profile 360","VMProtect 3.6.0 - x64",L"VMProtect 3.6.0 - x64"},
 {380,10,"kvm_profile 380","VMProtect 3.8.0 - x64",L"VMProtect 3.8.0 - x64"},
 {394,11,"kvm_profile 394","VMProtect 3.9.4 - x64",L"VMProtect 3.9.4 - x64"},
 {3101,12,"kvm_profile 3101","VMProtect 3.10.1 - x64",L"VMProtect 3.10.1 - x64"}};
static constexpr unsigned profileCount=sizeof(profiles)/sizeof(profiles[0]);
static unsigned selected=0;
static bool cpuidOption=true,firmwareOption=true,moduleOption=true;
static bool scansFirmware(){return profiles[selected].id==394||profiles[selected].id==3101;}
static duint firmwareScanner=0,moduleQuery=0;
static uint64_t leaf1Hits=0,vendorHits=0,privilegeHits=0;
struct Owned {duint pc;std::string name,command;BPXTYPE kind=bp_memory;};
struct Pending {duint site,sp;unsigned leaf;};
static std::vector<Owned> owned;
static std::map<DWORD,Pending> pending;
static std::vector<duint> sites;
static std::map<duint,unsigned> hot;
static void log(const char* s){_plugin_logprintf("[KozVM] %s\n",s);FILE* f=nullptr;auto path=ini+L".log";if(_wfopen_s(&f,path.c_str(),L"a")==0&&f){fprintf(f,"%s\n",s);fclose(f);}}
static std::string hex(duint x){char b[32];sprintf_s(b,"%llX",static_cast<unsigned long long>(x));return b;}
static bool cmd(const std::string& s){return DbgCmdExecDirect(s.c_str());}
static void menus(){if(menuReady){for(unsigned i=0;i<profileCount;++i)_plugin_menuentrysetchecked(handle,profiles[i].menu,enabled&&selected==i);_plugin_menuentrysetchecked(handle,2,!enabled);_plugin_menuentrysetchecked(handle,5,autoArm);}}
static void save(){wchar_t id[16];swprintf_s(id,L"%d",profiles[selected].id);WritePrivateProfileStringW(L"Settings",L"Profile",id,ini.c_str());WritePrivateProfileStringW(L"Settings",L"Enabled",enabled?L"1":L"0",ini.c_str());WritePrivateProfileStringW(L"Settings",L"AutoArm",autoArm?L"1":L"0",ini.c_str());WritePrivateProfileStringW(L"Options",L"CPUID",cpuidOption?L"1":L"0",ini.c_str());WritePrivateProfileStringW(L"Options",L"Firmware",firmwareOption?L"1":L"0",ini.c_str());WritePrivateProfileStringW(L"Options",L"Sandboxie",moduleOption?L"1":L"0",ini.c_str());menus();}
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
 if(ok){armed=false;pending.clear();sites.clear();}
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
static bool firmwareSignature(duint pc){
 unsigned char b[1400]{};if(!DbgMemRead(pc,b,sizeof(b)))return false;
 const unsigned char head[]={0x48,0x89,0x5c,0x24,0x08,0x45,0x33,0xc0,0x48,0x85,0xd2};
 const unsigned char head3101[]={0x48,0x89,0x5c,0x24,0x08,0x45,0x2b,0xc0,0xf9,0x48,0x85,0xd2};
 if(profiles[selected].id==3101){if(memcmp(b,head3101,sizeof(head3101)))return false;}
 else if(memcmp(b,head,sizeof(head)))return false;
 // Validate all eight literal comparison sequences, not just a prologue.
 for(const char* marker:{"QEMU","Oracle","innotek","VirtualBox","Virtual Platform","VMware","Parallels","777777"}){
  size_t from=0;
  for(size_t i=0;marker[i];++i){
   unsigned char first[]={0x41,0x80,0x39,static_cast<unsigned char>(marker[i])};
   unsigned char rest[]={0x41,0x80,0x7c,0x08,static_cast<unsigned char>(i),static_cast<unsigned char>(marker[i])};
   const auto* pattern=i?rest:first;size_t len=i?sizeof(rest):sizeof(first);
   auto match=std::search(b+from,b+sizeof(b),pattern,pattern+len);
   if(match==b+sizeof(b))return false;from=static_cast<size_t>(match-b)+len;
  }
 }
 return true;
}
static bool hardware(duint pc){
 if(DbgGetBpxTypeAt(pc)!=bp_none)return false;
 Owned o{pc,"KVM_HW_"+hex(pc),"kvm_hit",bp_hardware};
 if(!cmd("bphws "+hex(pc)+",x,1"))return false;
 if(!cmd("SetHardwareBreakpointName "+hex(pc)+",\""+o.name+"\"")){cmd("bphwc "+hex(pc));return false;}
 owned.push_back(o);
 return cmd("SetHardwareBreakpointCommand "+hex(pc)+",kvm_hit")&&cmd("SetHardwareBreakpointCondition "+hex(pc)+",0")&&cmd("SetHardwareBreakpointCommandCondition "+hex(pc)+",1")&&cmd("SetHardwareBreakpointFastResume "+hex(pc)+",0")&&cmd("SetHardwareBreakpointSilent "+hex(pc)+",1");
}
static bool returnZero(){duint dest=0,sp=R::GetCSP();return DbgMemRead(sp,&dest,sizeof(dest))&&R::SetRAX(0)&&R::SetCSP(sp+sizeof(duint))&&R::SetCIP(dest);}
static bool scan(std::vector<duint>& result){
 firmwareScanner=0;moduleQuery=0;
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
   if(scansFirmware()&&firmwareOption)for(duint j=0;j+1<len&&j<4096;++j)if(buf[j]==0x48&&buf[j+1]==0x89&&firmwareSignature(base+begin+off+j)){
    if(firmwareScanner){log("Multiple firmware scanners; refusing ambiguous setup.");return false;}firmwareScanner=base+begin+off+j;
   }
   for(duint j=0;j+1<len&&j<4096;++j)if(buf[j]==0x0f&&buf[j+1]==0xa2&&(profiles[selected].id>=380||handler(base+begin+off+j))){
    result.push_back(base+begin+off+j);if(result.size()>(profiles[selected].id>=380?4096u:256u)){log("Too many candidates; refusing this layout.");return false;}
   }
  }
 }
 if(scansFirmware()){if(moduleOption)moduleQuery=DbgValFromString("kernelbase.GetModuleHandleA");if((firmwareOption&&!firmwareScanner)||(moduleOption&&!moduleQuery)){log("Firmware scanner or module API could not be resolved.");return false;}}
 return !cpuidOption||!result.empty();
}
static bool armExtra(){
 if(!scansFirmware())return true;
 if((firmwareOption&&!hardware(firmwareScanner))||(moduleOption&&!hardware(moduleQuery))){log("Firmware/module breakpoint setup failed; rolling back.");disarm();return false;}
 log("Selected firmware/module monitoring armed.");return true;
}
static bool apply(int,char**){std::lock_guard<std::recursive_mutex> lock(gate);
 if(!DbgIsDebugging()||DbgIsRunning()){log("Load and pause an x64 target first.");return false;}
 if(!disarm())return false;if(!enabled){log("Disabled.");return true;}
 std::vector<duint> candidates;
 if(!scan(candidates)){log("No supported CPUID handler layout, or scan failed. Profile not armed.");return false;}
 if(!cpuidOption){if(!scansFirmware()){log("CPUID is disabled; this profile has no independent firmware/module hooks.");return true;}return armExtra();}
 BPMAP existing{};DbgGetBpList(bp_memory,&existing);
 bool conflict=false;for(int i=0;i<existing.count;++i)for(auto pc:candidates)if((existing.bp[i].addr&~duint(4095))==(pc&~duint(4095)))conflict=true;
 if(existing.bp)BridgeFree(existing.bp);
 if(conflict){log("Existing memory breakpoint page conflict; setup aborted.");return false;}
 std::vector<duint> pages;for(auto pc:candidates){auto page=pc&~duint(4095);if(std::find(pages.begin(),pages.end(),page)==pages.end())pages.push_back(page);}
 for(auto pc:pages)if(!add(pc)){log("Memory breakpoint setup failed; rolling back.");disarm();return false;}
 sites=std::move(candidates);hot.clear();leaf1Hits=vendorHits=privilegeHits=0;armed=true;
 char message[160];sprintf_s(message,"Profile %d armed: %u CPUID candidates; code bytes unchanged.",profiles[selected].id,static_cast<unsigned>(sites.size()));log(message);return true;
}
static void accelerate(duint pc){
 duint page=pc&~duint(4095);
 auto mem=std::find_if(owned.begin(),owned.end(),[&](const Owned& o){return o.kind==bp_memory&&o.pc==page;});
 // 3.6 performs more scattered startup work before its dense loop.
 // Avoid filling all slots with those early, moderately active pages.
 const unsigned threshold=profiles[selected].id>=360?65536u:8192u;
 if(mem==owned.end())return;
 unsigned visits=++hot[page];
 if(scansFirmware()?visits%threshold!=0:visits!=threshold)return;
 Owned guard=*mem;
 BPMAP map{};DbgGetBpList(bp_hardware,&map);unsigned used=0;
 for(int i=0;i<map.count;++i)if(map.bp[i].slot<4)used|=1u<<map.bp[i].slot;
 if(map.bp)BridgeFree(map.bp);
 auto dr7=R::Get(R::DR7);for(unsigned i=0;i<4;++i)if((dr7>>(i*2))&3u)used|=1u<<i;
 unsigned free=0;for(unsigned i=0;i<4;++i)if(!(used&(1u<<i)))++free;
 std::vector<duint> targets;for(auto x:sites)if((x&~duint(4095))==page)targets.push_back(x);
 if(targets.empty()||targets.size()>4)return;
 if(scansFirmware()&&targets.size()>free){
  std::vector<duint> evict;
  for(const auto& o:owned)if(o.kind==bp_hardware){duint old=o.pc&~duint(4095);if(hot[old]*2u<visits&&std::find(evict.begin(),evict.end(),old)==evict.end())evict.push_back(old);}
  for(auto old:evict){
   if(targets.size()<=free)break;
   std::vector<Owned> group;for(const auto& o:owned)if(o.kind==bp_hardware&&(o.pc&~duint(4095))==old)group.push_back(o);
   if(!std::all_of(group.begin(),group.end(),same))continue;
   // Restore page coverage before releasing any owned hardware slot.
   if(!add(old))return;
   for(const auto& o:group){if(!cmd("bphwc "+hex(o.pc)))return;owned.erase(std::remove_if(owned.begin(),owned.end(),[&](const Owned& v){return v.kind==bp_hardware&&v.pc==o.pc;}),owned.end());++free;}
   log("Recycled owned hardware slots; previous page remains guarded.");
  }
 }
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
static bool hit(int,char**){std::lock_guard<std::recursive_mutex> lock(gate);
 duint pc=R::GetCIP();
 if(scansFirmware()&&firmwareOption&&pc==firmwareScanner){if(!returnZero()){log("Firmware return emulation failed.");return false;}log("Firmware scanner returned clean.");return true;}
 if(scansFirmware()&&moduleOption&&pc==moduleQuery){char name[13]{};if(DbgMemRead(R::GetRCX(),name,sizeof(name)-1)&&_stricmp(name,"sbiedll.dll")==0){if(!returnZero())return false;log("Sandboxie module query returned absent.");disarm();}return true;}
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
   if(clean){armed=false;sites.clear();char message[128];sprintf_s(message,"Profile %d accepted CPUID path complete; all KozVM guards removed.",profiles[selected].id);log(message);if(scansFirmware()){if(!armExtra()){log("Firmware/module breakpoint setup failed; pausing.");DbgCmdExec("pause");return false;}log("Firmware and module monitoring armed.");}}else log("Guard cleanup failed; pause and inspect before continuing.");
  }
 }
 return ok;
}
static bool status(int,char**){std::lock_guard<std::recursive_mutex> lock(gate);_plugin_logprintf("[KozVM] profile=%d enabled=%u armed=%u handlers=%u leaf1=%llu vendor=%llu privilege=%llu pending=%u\n",profiles[selected].id,enabled,armed,static_cast<unsigned>(sites.size()),leaf1Hits,vendorHits,privilegeHits,static_cast<unsigned>(pending.size()));return true;}
static bool profile(int argc,char** argv){std::lock_guard<std::recursive_mutex> lock(gate);
 unsigned next=profileCount;if(argc==2)for(unsigned i=0;i<profileCount;++i)if(strcmp(argv[1],profiles[i].command+12)==0)next=i;
 if(argc!=2||(next==profileCount&&strcmp(argv[1],"off"))){log("Usage: kvm_profile 331|340|350|360|380|394|3101|off");return false;}
 if(!disarm())return false;enabled=next!=profileCount;if(enabled)selected=next;save();if(DbgIsDebugging()&&enabled)return apply(0,nullptr);return true;
}
static INT_PTR CALLBACK dialog(HWND wnd,UINT msg,WPARAM wp,LPARAM){
 if(msg==WM_INITDIALOG){dialogWindow=wnd;for(const auto& p:profiles)SendDlgItemMessageW(wnd,110,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(p.wide));SendDlgItemMessageW(wnd,110,CB_SETCURSEL,selected,0);CheckDlgButton(wnd,111,autoArm?BST_CHECKED:BST_UNCHECKED);CheckDlgButton(wnd,120,enabled?BST_CHECKED:BST_UNCHECKED);
  HWND tip=CreateWindowExW(WS_EX_TOPMOST,TOOLTIPS_CLASSW,nullptr,WS_POPUP|TTS_ALWAYSTIP,CW_USEDEFAULT,CW_USEDEFAULT,CW_USEDEFAULT,CW_USEDEFAULT,wnd,nullptr,instance,nullptr);
  const wchar_t* tips[]={L"CPUID: set hypervisor bit 31, Microsoft Hv vendor and CreatePartitions bit as one compatible policy. Turning this off leaves CPU results unchanged.",L"3.9.4 / 3.10.1 only: return clean from the identified firmware scanner. Earlier profiles skip this path via CPUID; they have no independent firmware hook.",L"3.9.4 / 3.10.1 only: return absent for GetModuleHandleA(\"sbiedll.dll\"). Other module names are not changed."};
  for(int i=0;i<3;++i){TOOLINFOW ti{};ti.cbSize=sizeof(ti);ti.uFlags=TTF_IDISHWND|TTF_SUBCLASS;ti.hwnd=wnd;ti.uId=reinterpret_cast<UINT_PTR>(GetDlgItem(wnd,200+i));ti.lpszText=const_cast<wchar_t*>(tips[i]);SendMessageW(tip,TTM_ADDTOOLW,0,reinterpret_cast<LPARAM>(&ti));}SendMessageW(tip,TTM_SETMAXTIPWIDTH,0,360);
  CheckDlgButton(wnd,121,cpuidOption?BST_CHECKED:BST_UNCHECKED);CheckDlgButton(wnd,122,firmwareOption?BST_CHECKED:BST_UNCHECKED);CheckDlgButton(wnd,123,moduleOption?BST_CHECKED:BST_UNCHECKED);EnableWindow(GetDlgItem(wnd,122),scansFirmware());EnableWindow(GetDlgItem(wnd,123),scansFirmware());
  return TRUE;}
 if(msg==WM_COMMAND){
  if(LOWORD(wp)==110&&HIWORD(wp)==CBN_SELCHANGE){auto i=SendDlgItemMessageW(wnd,110,CB_GETCURSEL,0,0);bool extra=i>=0&&i<profileCount&&(profiles[i].id==394||profiles[i].id==3101);EnableWindow(GetDlgItem(wnd,122),extra);EnableWindow(GetDlgItem(wnd,123),extra);return TRUE;}
  if(LOWORD(wp)==IDCANCEL){EndDialog(wnd,0);return TRUE;}
  if(LOWORD(wp)==150){MessageBoxW(wnd,L"KozVM x64\n\nCreator: Ivan Kozlovsky\ncontact@ivankozlovsky.com\nivankozlovsky.com\n\nVMProtect 3.3.1 / 3.4.0 / 3.5.0 / 3.6.0 / 3.8.0 / 3.9.4 / 3.10.1 - x64",L"About KozVM",MB_OK|MB_ICONINFORMATION);return TRUE;}
  if(LOWORD(wp)==IDOK){std::lock_guard<std::recursive_mutex> lock(gate);if(!disarm()){MessageBoxW(wnd,L"Pause the target and check the log before applying.",L"KozVM",MB_OK|MB_ICONWARNING);return TRUE;}auto choice=SendDlgItemMessageW(wnd,110,CB_GETCURSEL,0,0);if(choice>=0&&choice<profileCount)selected=static_cast<unsigned>(choice);enabled=IsDlgButtonChecked(wnd,120)==BST_CHECKED;autoArm=IsDlgButtonChecked(wnd,111)==BST_CHECKED;cpuidOption=IsDlgButtonChecked(wnd,121)==BST_CHECKED;firmwareOption=IsDlgButtonChecked(wnd,122)==BST_CHECKED;moduleOption=IsDlgButtonChecked(wnd,123)==BST_CHECKED;save();if(DbgIsDebugging())DbgCmdExec("kvm_apply");EndDialog(wnd,1);return TRUE;}
 }
 if(msg==WM_CLOSE){EndDialog(wnd,0);return TRUE;}if(msg==WM_DESTROY)dialogWindow=nullptr;return FALSE;
}
static void show(){if(dialogWindow){SetForegroundWindow(dialogWindow);return;}DialogBoxParamW(instance,MAKEINTRESOURCEW(101),owner,dialog,0);}
static bool settings(int,char**){GuiExecuteOnGuiThread(show);return true;}
static void cleanSavedBreakpoints(){
 for(auto kind:{bp_memory,bp_hardware}){
  BPMAP map{};DbgGetBpList(kind,&map);std::vector<duint> stale;
  for(int i=0;i<map.count;++i){auto& b=map.bp[i];
   if(strncmp(b.name,"KVM_",4)==0&&strcmp(b.commandText,"kvm_hit")==0&&strcmp(b.breakCondition,"0")==0&&strcmp(b.commandCondition,"1")==0&&b.silent&&!b.fastResume)stale.push_back(b.addr);
  }
  if(map.bp)BridgeFree(map.bp);
  for(auto pc:stale)if(!cmd(std::string(kind==bp_memory?"bpmc ":"bphwc ")+hex(pc)))log("Could not remove a saved KozVM breakpoint.");
 }
}
static void callback(CBTYPE type,void* data){
 if(type==CB_SYSTEMBREAKPOINT){std::lock_guard<std::recursive_mutex> lock(gate);cleanSavedBreakpoints();if(enabled&&autoArm)DbgCmdExec("kvm_apply");}
 else if(type==CB_STOPPINGDEBUG||type==CB_DETACH){std::lock_guard<std::recursive_mutex> lock(gate);disarm(true);}
 else if(type==CB_INITDEBUG||type==CB_STOPDEBUG){std::lock_guard<std::recursive_mutex> lock(gate);armed=false;sites.clear();owned.clear();pending.clear();leaf1Hits=vendorHits=privilegeHits=0;}
 else if(type==CB_EXITTHREAD){std::lock_guard<std::recursive_mutex> lock(gate);pending.erase(static_cast<PLUG_CB_EXITTHREAD*>(data)->dwThreadId);}
 else if(type==CB_MENUENTRY){int id=static_cast<PLUG_CB_MENUENTRY*>(data)->hEntry;for(const auto& p:profiles)if(id==p.menu)DbgCmdExec(p.command);if(id==2)DbgCmdExec("kvm_profile off");if(id==3)settings(0,nullptr);if(id==4)DbgCmdExec("kvm_apply");if(id==5){std::lock_guard<std::recursive_mutex> lock(gate);autoArm=!autoArm;save();}if(id==6)DbgCmdExec("kvm_status");}
}
extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* init){handle=init->pluginHandle;init->sdkVersion=PLUG_SDKVERSION;init->pluginVersion=1;strcpy_s(init->pluginName,"KozVM x64");wchar_t path[MAX_PATH]{};GetModuleFileNameW(instance,path,MAX_PATH);ini=path;ini+=L".ini";enabled=GetPrivateProfileIntW(L"Settings",L"Enabled",1,ini.c_str())!=0;autoArm=GetPrivateProfileIntW(L"Settings",L"AutoArm",1,ini.c_str())!=0;
 cpuidOption=GetPrivateProfileIntW(L"Options",L"CPUID",1,ini.c_str())!=0;firmwareOption=GetPrivateProfileIntW(L"Options",L"Firmware",1,ini.c_str())!=0;moduleOption=GetPrivateProfileIntW(L"Options",L"Sandboxie",1,ini.c_str())!=0;
 int savedProfile=GetPrivateProfileIntW(L"Settings",L"Profile",331,ini.c_str());for(unsigned i=0;i<profileCount;++i)if(profiles[i].id==savedProfile)selected=i;
 _plugin_registercommand(handle,"kvm_apply",apply,false);_plugin_registercommand(handle,"kvm_profile",profile,false);_plugin_registercommand(handle,"kvm_settings",settings,false);_plugin_registercommand(handle,"kvm_status",status,false);_plugin_registercommand(handle,"kvm_hit",hit,true);
 for(auto t:{CB_SYSTEMBREAKPOINT,CB_INITDEBUG,CB_STOPPINGDEBUG,CB_DETACH,CB_STOPDEBUG,CB_EXITTHREAD,CB_MENUENTRY})_plugin_registercallback(handle,t,callback);log("Loaded x64 profiles: 331, 340, 350, 360, 380, 394, 3101.");return true;}
extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* s){owner=s->hwndDlg;for(const auto& p:profiles)_plugin_menuaddentry(s->hMenu,p.menu,p.label);_plugin_menuaddentry(s->hMenu,2,"Disabled");_plugin_menuaddseparator(s->hMenu);_plugin_menuaddentry(s->hMenu,3,"Settings...");_plugin_menuaddentry(s->hMenu,4,"Apply to paused session");_plugin_menuaddentry(s->hMenu,5,"Auto-enable on start");_plugin_menuaddentry(s->hMenu,6,"Status");menuReady=true;menus();}
extern "C" __declspec(dllexport) bool plugstop(){std::lock_guard<std::recursive_mutex> lock(gate);if(dialogWindow||!disarm())return false;for(auto n:{"kvm_apply","kvm_profile","kvm_settings","kvm_status","kvm_hit"})_plugin_unregistercommand(handle,n);return true;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD reason,LPVOID){if(reason==DLL_PROCESS_ATTACH){instance=h;DisableThreadLibraryCalls(h);}return TRUE;}
