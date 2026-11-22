/* Copyright (C) 2026 ItsJokerZz

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>. */


#pragma once

#include <stdint.h>

typedef enum sysmodule_id {
  SYSMODULE_INTERNAL_AUDIO_OUT = 0x80000001,
  SYSMODULE_INTERNAL_SYSTEM_SERVICE = 0x80000010,
  SYSMODULE_INTERNAL_VIDEO_OUT = 0x80000022,
  SYSMODULE_INTERNAL_NET = 0x8000001c,
  SYSMODULE_INTERNAL_USER_SERVICE = 0x80000011,
  SYSMODULE_INTERNAL_PAD = 0x80000024,
  SYSMODULE_INTERNAL_SYS_UTIL = 0x80000026,
  SYSMODULE_INTERNAL_GNM_DRIVER = 0x80000052,
  SYSMODULE_INTERNAL_NET_CTL = 0x80000009,
  SYSMODULE_INTERNAL_HTTP = 0x8000000a,
  SYSMODULE_INTERNAL_SSL = 0x8000000b,
} sysmodule_id_t;

typedef enum sysmodule_public_id {
  SYSMODULE_MESSAGE_DIALOG = 0x00a4,
  SYSMODULE_IME_DIALOG = 0x0096,
  SYSMODULE_SAVE_DATA_DIALOG = 0x00a0,
  SYSMODULE_APP_CONTENT = 0x00b4,
  SYSMODULE_NP_TROPHY = 0x00ad,
} sysmodule_public_id_t;

typedef struct sysmodule_entry {
  const char *name;
  uint32_t id;
} sysmodule_entry_t;

static const sysmodule_entry_t sysmodule_internal_table[]
    __attribute__((unused)) = {
      { "libSceAudioOut.sprx", 0x80000001 },
      { "libSceAudioIn.sprx", 0x80000002 },
      { "libSceAvcap.sprx", 0x80000003 },
      { "libSceSysCore.sprx", 0x80000004 },
      { "libSceCdlgUtilServer.sprx", 0x80000007 },
      { "libSceKeyboard.sprx", 0x80000008 },
      { "libSceNetCtl.sprx", 0x80000009 },
      { "libSceHttp.sprx", 0x8000000a },
      { "libSceSsl.sprx", 0x8000000b },
      { "libSceNpCommon.sprx", 0x8000000c },
      { "libSceNpManager.sprx", 0x8000000d },
      { "libSceNpWebApi.sprx", 0x8000000e },
      { "libSceSaveData.sprx", 0x8000000f },
      { "libSceSystemService.sprx", 0x80000010 },
      { "libSceUserService.sprx", 0x80000011 },
      { "libSceVisionManager.sprx", 0x80000012 },
      { "libSceAc3Enc.sprx", 0x80000013 },
      { "libSceAppInstUtil.sprx", 0x80000014 },
      { "libSceVdecCore.sprx", 0x80000015 },
      { "libSceHidControl.sprx", 0x80000017 },
      { "libSceCommonDialog.sprx", 0x80000018 },
      { "libScePerf.sprx", 0x80000019 },
      { "libSceCamera.sprx", 0x8000001a },
      { "libSceNpSns.sprx", 0x8000001b },
      { "libSceNet.sprx", 0x8000001c },
      { "libSceIpmi.sprx", 0x8000001d },
      { "libSceMbus.sprx", 0x8000001e },
      { "libSceRegMgr.sprx", 0x8000001f },
      { "libSceRtc.sprx", 0x80000020 },
      { "libSceAvSetting.sprx", 0x80000021 },
      { "libSceVideoOut.sprx", 0x80000022 },
      { "libSceAjm.sprx", 0x80000023 },
      { "libScePad.sprx", 0x80000024 },
      { "libSceDbg.sprx", 0x80000025 },
      { "libSceSysUtil.sprx", 0x80000026 },
      { "libSceMarlin.sprx", 0x80000027 },
      { "libSceDtsEnc.sprx", 0x80000028 },
      { "libSceDipsw.sprx", 0x80000029 },
      { "libSceBgft.sprx", 0x8000002a },
      { "libSceAudiodecCpuDts.sprx", 0x8000002b },
      { "libSceAudiodecCpuDtsHdLbr.sprx", 0x8000002c },
      { "libSceAudiodecCpuDtsHdMa.sprx", 0x8000002d },
      { "libSceAudiodecCpuLpcm.sprx", 0x8000002e },
      { "libSceIduUtil.sprx", 0x8000002f },
      { "libScePsm.sprx", 0x80000030 },
      { "libSceKbEmulate.sprx", 0x80000031 },
      { "libSceAppChecker.sprx", 0x80000032 },
      { "libSceNpGriefReport.sprx", 0x80000033 },
      { "libSceWeb.sprx", 0x80000034 },
      { "libSceVdecSavc.sprx", 0x80000035 },
      { "libSceVdecSavc2.sprx", 0x80000036 },
      { "libSceVshctl.sprx", 0x80000037 },
      { "libSceAudiodReport.sprx", 0x8000003a },
      { "libSceSulphaDrv.sprx", 0x8000003b },
      { "libSceVdecShevc.sprx", 0x8000003c },
      { "libSceDbgAssist.sprx", 0x8000003d },
      { "libSceOttvCapture.sprx", 0x8000003e },
      { "libSceTtsCoreEnUs.sprx", 0x80000041 },
      { "libSceTtsCoreJp.sprx", 0x80000042 },
      { "libSceOpusCeltEnc.sprx", 0x80000043 },
      { "libSceOpusCeltDec.sprx", 0x80000044 },
      { "libSceVideoOutSecondary.sprx", 0x80000046 },
      { "libSceGnmResourceRegistration.sprx", 0x80000047 },
      { "libSceScm.sprx", 0x80000049 },
      { "libSceAvPlayerStreaming.sprx", 0x80000050 },
      { "libSceAudiodecCpuAlac.sprx", 0x80000051 },
      { "libSceGnmDriver.sprx", 0x80000052 },
      { "libSceAudiodecCpuFlac.sprx", 0x80000053 },
      { "libSceSrcUtl.sprx", 0x80000054 },
      { "libSceS3da.sprx", 0x80000055 },
      { "libSceDseehx.sprx", 0x80000056 },
      { "libSceDataTransfer.sprx", 0x80000057 },
      { "libSceAbstractStorage.sprx", 0x80000058 },
      { "libSceImageUtil.sprx", 0x80000059 },
      { "libSceMetadataReaderWriter.sprx", 0x8000005a },
      { "libSceJpegParser.sprx", 0x8000005b },
      { "libSceGvMp4Parser.sprx", 0x8000005c },
      { "libScePngParser.sprx", 0x8000005d },
      { "libSceGifParser.sprx", 0x8000005e },
      { "libSceAbstractLocal.sprx", 0x8000005f },
      { "libSceAbstractFacebook.sprx", 0x80000060 },
      { "libSceAbstractYoutube.sprx", 0x80000061 },
      { "libSceAbstractTwitter.sprx", 0x80000062 },
      { "libSceAbstractDailymotion.sprx", 0x80000063 },
      { "libScePrecompiledShaders.sprx", 0x80000064 },
      { "libSceLibreSsl.sprx", 0x80000065 },
      { "libSceOpusSilkEnc.sprx", 0x80000068 },
      { "libSceOpusDec.sprx", 0x80000069 },
      { "libSceJscCompiler.sprx", 0x8000006c },
      { "libSceVideoCoreServerInterface.sprx", 0x8000006d },
      { "libSceJitBridge.sprx", 0x8000006e },
    };
