##
## Auto Generated makefile by CodeLite IDE
## any manual changes will be erased      
##
## Debug
ProjectName            :=TLSClient
ConfigurationName      :=Debug
WorkspacePath          := "/dati/AdvancedProgramming"
ProjectPath            := "/dati/AdvancedProgramming"
IntermediateDirectory  :=./bin
OutDir                 := $(IntermediateDirectory)
CurrentFileName        :=
CurrentFilePath        :=
CurrentFileFullPath    :=
User                   :=Alessandro Melloni
Date                   :=21/01/16
CodeLitePath           :="/home/ale/.codelite"
LinkerName             :=/usr/bin/g++
SharedObjectLinkerName :=/usr/bin/g++ -shared -fPIC
ObjectSuffix           :=.o
DependSuffix           :=.o.d
PreprocessSuffix       :=.i
DebugSwitch            :=-g 
IncludeSwitch          :=-I
LibrarySwitch          :=-l
OutputSwitch           :=-o 
LibraryPathSwitch      :=-L
PreprocessorSwitch     :=-D
SourceSwitch           :=-c 
OutputFile             :=$(IntermediateDirectory)/$(ProjectName)
Preprocessors          :=
ObjectSwitch           :=-o 
ArchiveOutputSwitch    := 
PreprocessOnlySwitch   :=-E
ObjectsFileList        :="TLSClient.txt"
PCHCompileFlags        :=
MakeDirCommand         :=mkdir -p
LinkOptions            :=  -lssl -lcrypto -pthread
IncludePath            :=  $(IncludeSwitch). $(IncludeSwitch)include $(IncludeSwitch)include/HandshakeMessages 
IncludePCH             := 
RcIncludePath          := 
Libs                   := 
ArLibs                 :=  
LibPath                := $(LibraryPathSwitch). 

##
## Common variables
## AR, CXX, CC, AS, CXXFLAGS and CFLAGS can be overriden using an environment variables
##
AR       := /usr/bin/ar rcu
CXX      := /usr/bin/g++
CC       := /usr/bin/gcc
CXXFLAGS :=   $(Preprocessors)
CFLAGS   :=  -g -O0 -Wall -std=gnu99 $(Preprocessors)
ASFLAGS  := 
AS       := /usr/bin/as


##
## User defined environment variables
##
CodeLiteDir:=/usr/share/codelite
Objects0=$(IntermediateDirectory)/src_Crypto.c$(ObjectSuffix) $(IntermediateDirectory)/src_handshakeConstants.c$(ObjectSuffix) $(IntermediateDirectory)/src_ServerClientBasic.c$(ObjectSuffix) $(IntermediateDirectory)/src_ServerClientHandshakeProtocol.c$(ObjectSuffix) $(IntermediateDirectory)/src_ServerClientRecordProtocol.c$(ObjectSuffix) $(IntermediateDirectory)/src_TLSClient.c$(ObjectSuffix) $(IntermediateDirectory)/src_TLSServer.c$(ObjectSuffix) $(IntermediateDirectory)/HandshakeMessages_Certificate.c$(ObjectSuffix) $(IntermediateDirectory)/HandshakeMessages_ServerClientHello.c$(ObjectSuffix) $(IntermediateDirectory)/HandshakeMessages_ServerClientKeyExchange.c$(ObjectSuffix) \
	$(IntermediateDirectory)/Target_client.c$(ObjectSuffix) 



Objects=$(Objects0) 

##
## Main Build Targets 
##
.PHONY: all clean PreBuild PrePreBuild PostBuild MakeIntermediateDirs
all: $(OutputFile)

$(OutputFile): $(IntermediateDirectory)/.d $(Objects) 
	@$(MakeDirCommand) $(@D)
	@echo "" > $(IntermediateDirectory)/.d
	@echo $(Objects0)  > $(ObjectsFileList)
	$(LinkerName) $(OutputSwitch)$(OutputFile) @$(ObjectsFileList) $(LibPath) $(Libs) $(LinkOptions)

MakeIntermediateDirs:
	@test -d ./bin || $(MakeDirCommand) ./bin


$(IntermediateDirectory)/.d:
	@test -d ./bin || $(MakeDirCommand) ./bin

PreBuild:


##
## Objects
##
$(IntermediateDirectory)/src_Crypto.c$(ObjectSuffix): src/Crypto.c $(IntermediateDirectory)/src_Crypto.c$(DependSuffix)
	$(CC) $(SourceSwitch) "/dati/AdvancedProgramming/src/Crypto.c" $(CFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/src_Crypto.c$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/src_Crypto.c$(DependSuffix): src/Crypto.c
	@$(CC) $(CFLAGS) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/src_Crypto.c$(ObjectSuffix) -MF$(IntermediateDirectory)/src_Crypto.c$(DependSuffix) -MM "src/Crypto.c"

$(IntermediateDirectory)/src_Crypto.c$(PreprocessSuffix): src/Crypto.c
	@$(CC) $(CFLAGS) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/src_Crypto.c$(PreprocessSuffix) "src/Crypto.c"

$(IntermediateDirectory)/src_handshakeConstants.c$(ObjectSuffix): src/handshakeConstants.c $(IntermediateDirectory)/src_handshakeConstants.c$(DependSuffix)
	$(CC) $(SourceSwitch) "/dati/AdvancedProgramming/src/handshakeConstants.c" $(CFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/src_handshakeConstants.c$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/src_handshakeConstants.c$(DependSuffix): src/handshakeConstants.c
	@$(CC) $(CFLAGS) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/src_handshakeConstants.c$(ObjectSuffix) -MF$(IntermediateDirectory)/src_handshakeConstants.c$(DependSuffix) -MM "src/handshakeConstants.c"

$(IntermediateDirectory)/src_handshakeConstants.c$(PreprocessSuffix): src/handshakeConstants.c
	@$(CC) $(CFLAGS) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/src_handshakeConstants.c$(PreprocessSuffix) "src/handshakeConstants.c"

$(IntermediateDirectory)/src_ServerClientBasic.c$(ObjectSuffix): src/ServerClientBasic.c $(IntermediateDirectory)/src_ServerClientBasic.c$(DependSuffix)
	$(CC) $(SourceSwitch) "/dati/AdvancedProgramming/src/ServerClientBasic.c" $(CFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/src_ServerClientBasic.c$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/src_ServerClientBasic.c$(DependSuffix): src/ServerClientBasic.c
	@$(CC) $(CFLAGS) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/src_ServerClientBasic.c$(ObjectSuffix) -MF$(IntermediateDirectory)/src_ServerClientBasic.c$(DependSuffix) -MM "src/ServerClientBasic.c"

$(IntermediateDirectory)/src_ServerClientBasic.c$(PreprocessSuffix): src/ServerClientBasic.c
	@$(CC) $(CFLAGS) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/src_ServerClientBasic.c$(PreprocessSuffix) "src/ServerClientBasic.c"

$(IntermediateDirectory)/src_ServerClientHandshakeProtocol.c$(ObjectSuffix): src/ServerClientHandshakeProtocol.c $(IntermediateDirectory)/src_ServerClientHandshakeProtocol.c$(DependSuffix)
	$(CC) $(SourceSwitch) "/dati/AdvancedProgramming/src/ServerClientHandshakeProtocol.c" $(CFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/src_ServerClientHandshakeProtocol.c$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/src_ServerClientHandshakeProtocol.c$(DependSuffix): src/ServerClientHandshakeProtocol.c
	@$(CC) $(CFLAGS) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/src_ServerClientHandshakeProtocol.c$(ObjectSuffix) -MF$(IntermediateDirectory)/src_ServerClientHandshakeProtocol.c$(DependSuffix) -MM "src/ServerClientHandshakeProtocol.c"

$(IntermediateDirectory)/src_ServerClientHandshakeProtocol.c$(PreprocessSuffix): src/ServerClientHandshakeProtocol.c
	@$(CC) $(CFLAGS) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/src_ServerClientHandshakeProtocol.c$(PreprocessSuffix) "src/ServerClientHandshakeProtocol.c"

$(IntermediateDirectory)/src_ServerClientRecordProtocol.c$(ObjectSuffix): src/ServerClientRecordProtocol.c $(IntermediateDirectory)/src_ServerClientRecordProtocol.c$(DependSuffix)
	$(CC) $(SourceSwitch) "/dati/AdvancedProgramming/src/ServerClientRecordProtocol.c" $(CFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/src_ServerClientRecordProtocol.c$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/src_ServerClientRecordProtocol.c$(DependSuffix): src/ServerClientRecordProtocol.c
	@$(CC) $(CFLAGS) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/src_ServerClientRecordProtocol.c$(ObjectSuffix) -MF$(IntermediateDirectory)/src_ServerClientRecordProtocol.c$(DependSuffix) -MM "src/ServerClientRecordProtocol.c"

$(IntermediateDirectory)/src_ServerClientRecordProtocol.c$(PreprocessSuffix): src/ServerClientRecordProtocol.c
	@$(CC) $(CFLAGS) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/src_ServerClientRecordProtocol.c$(PreprocessSuffix) "src/ServerClientRecordProtocol.c"

$(IntermediateDirectory)/src_TLSClient.c$(ObjectSuffix): src/TLSClient.c $(IntermediateDirectory)/src_TLSClient.c$(DependSuffix)
	$(CC) $(SourceSwitch) "/dati/AdvancedProgramming/src/TLSClient.c" $(CFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/src_TLSClient.c$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/src_TLSClient.c$(DependSuffix): src/TLSClient.c
	@$(CC) $(CFLAGS) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/src_TLSClient.c$(ObjectSuffix) -MF$(IntermediateDirectory)/src_TLSClient.c$(DependSuffix) -MM "src/TLSClient.c"

$(IntermediateDirectory)/src_TLSClient.c$(PreprocessSuffix): src/TLSClient.c
	@$(CC) $(CFLAGS) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/src_TLSClient.c$(PreprocessSuffix) "src/TLSClient.c"

$(IntermediateDirectory)/src_TLSServer.c$(ObjectSuffix): src/TLSServer.c $(IntermediateDirectory)/src_TLSServer.c$(DependSuffix)
	$(CC) $(SourceSwitch) "/dati/AdvancedProgramming/src/TLSServer.c" $(CFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/src_TLSServer.c$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/src_TLSServer.c$(DependSuffix): src/TLSServer.c
	@$(CC) $(CFLAGS) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/src_TLSServer.c$(ObjectSuffix) -MF$(IntermediateDirectory)/src_TLSServer.c$(DependSuffix) -MM "src/TLSServer.c"

$(IntermediateDirectory)/src_TLSServer.c$(PreprocessSuffix): src/TLSServer.c
	@$(CC) $(CFLAGS) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/src_TLSServer.c$(PreprocessSuffix) "src/TLSServer.c"

$(IntermediateDirectory)/HandshakeMessages_Certificate.c$(ObjectSuffix): src/HandshakeMessages/Certificate.c $(IntermediateDirectory)/HandshakeMessages_Certificate.c$(DependSuffix)
	$(CC) $(SourceSwitch) "/dati/AdvancedProgramming/src/HandshakeMessages/Certificate.c" $(CFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HandshakeMessages_Certificate.c$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HandshakeMessages_Certificate.c$(DependSuffix): src/HandshakeMessages/Certificate.c
	@$(CC) $(CFLAGS) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HandshakeMessages_Certificate.c$(ObjectSuffix) -MF$(IntermediateDirectory)/HandshakeMessages_Certificate.c$(DependSuffix) -MM "src/HandshakeMessages/Certificate.c"

$(IntermediateDirectory)/HandshakeMessages_Certificate.c$(PreprocessSuffix): src/HandshakeMessages/Certificate.c
	@$(CC) $(CFLAGS) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HandshakeMessages_Certificate.c$(PreprocessSuffix) "src/HandshakeMessages/Certificate.c"

$(IntermediateDirectory)/HandshakeMessages_ServerClientHello.c$(ObjectSuffix): src/HandshakeMessages/ServerClientHello.c $(IntermediateDirectory)/HandshakeMessages_ServerClientHello.c$(DependSuffix)
	$(CC) $(SourceSwitch) "/dati/AdvancedProgramming/src/HandshakeMessages/ServerClientHello.c" $(CFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HandshakeMessages_ServerClientHello.c$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HandshakeMessages_ServerClientHello.c$(DependSuffix): src/HandshakeMessages/ServerClientHello.c
	@$(CC) $(CFLAGS) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HandshakeMessages_ServerClientHello.c$(ObjectSuffix) -MF$(IntermediateDirectory)/HandshakeMessages_ServerClientHello.c$(DependSuffix) -MM "src/HandshakeMessages/ServerClientHello.c"

$(IntermediateDirectory)/HandshakeMessages_ServerClientHello.c$(PreprocessSuffix): src/HandshakeMessages/ServerClientHello.c
	@$(CC) $(CFLAGS) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HandshakeMessages_ServerClientHello.c$(PreprocessSuffix) "src/HandshakeMessages/ServerClientHello.c"

$(IntermediateDirectory)/HandshakeMessages_ServerClientKeyExchange.c$(ObjectSuffix): src/HandshakeMessages/ServerClientKeyExchange.c $(IntermediateDirectory)/HandshakeMessages_ServerClientKeyExchange.c$(DependSuffix)
	$(CC) $(SourceSwitch) "/dati/AdvancedProgramming/src/HandshakeMessages/ServerClientKeyExchange.c" $(CFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HandshakeMessages_ServerClientKeyExchange.c$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HandshakeMessages_ServerClientKeyExchange.c$(DependSuffix): src/HandshakeMessages/ServerClientKeyExchange.c
	@$(CC) $(CFLAGS) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HandshakeMessages_ServerClientKeyExchange.c$(ObjectSuffix) -MF$(IntermediateDirectory)/HandshakeMessages_ServerClientKeyExchange.c$(DependSuffix) -MM "src/HandshakeMessages/ServerClientKeyExchange.c"

$(IntermediateDirectory)/HandshakeMessages_ServerClientKeyExchange.c$(PreprocessSuffix): src/HandshakeMessages/ServerClientKeyExchange.c
	@$(CC) $(CFLAGS) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HandshakeMessages_ServerClientKeyExchange.c$(PreprocessSuffix) "src/HandshakeMessages/ServerClientKeyExchange.c"

$(IntermediateDirectory)/Target_client.c$(ObjectSuffix): src/Target/client.c $(IntermediateDirectory)/Target_client.c$(DependSuffix)
	$(CC) $(SourceSwitch) "/dati/AdvancedProgramming/src/Target/client.c" $(CFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/Target_client.c$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/Target_client.c$(DependSuffix): src/Target/client.c
	@$(CC) $(CFLAGS) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/Target_client.c$(ObjectSuffix) -MF$(IntermediateDirectory)/Target_client.c$(DependSuffix) -MM "src/Target/client.c"

$(IntermediateDirectory)/Target_client.c$(PreprocessSuffix): src/Target/client.c
	@$(CC) $(CFLAGS) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/Target_client.c$(PreprocessSuffix) "src/Target/client.c"


-include $(IntermediateDirectory)/*$(DependSuffix)
##
## Clean
##
clean:
	$(RM) -r ./bin/


