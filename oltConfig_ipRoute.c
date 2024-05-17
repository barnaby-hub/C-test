#include "actionDefine.h"

#include "cJSON.h"
#include "ossl.h"
#include "dev_def.h"
#include "cfg_db_id.h"
#include "sll_dev.h"
#include "sll_def.h"
#include "sll_l3Intf.h"
#include "oltConfig.h"
#include "sll_common.h"

#ifndef OLT_CFG_RET_l3_DIS
#define OLT_CFG_RET_l3_DIS "Error,L3 disable,feature invalid"
#endif



#ifndef M_OLT_CFG_IPROUTE_FUN_RET_CHECK
#define M_OLT_CFG_IPROUTE_FUN_RET_CHECK(_fun_ret_, _ok_val_, _rsp_val_, _ret_str_)\
{\
    if(_fun_ret_ != _ok_val_)\
    {\
		M_OLT_CFG_RETURN_ERR_AND_EXIT(_rsp_val_, _ret_str_);\
    }\
}
#endif

#ifndef M_OLT_CFG_IPROUTE_FUN_RET_ERR_AND_BREAK
#define M_OLT_CFG_IPROUTE_FUN_RET_ERR_AND_BREAK(_fun_ret_, _ok_val_, _rsp_val_, _ret_str_)\
{\
    if(_fun_ret_ != _ok_val_)\
    {\
		M_OLT_CFG_RETURN_ERR_AND_BREAK(_rsp_val_, _ret_str_);\
    }\
}
#endif


static void getStaticIpRouteTable(Webs *wp)
{
	cJSON *jsonArray = POS_NULL, *jsonObj = POS_NULL, *jsonData=POS_NULL;
	char *jsonStr = POS_NULL;
	POS_UINT32 upLinkSlotId;
	POS_UINT32 upLinkPort;
	SLL_L3_INTF_ROUTE_T ipRouteCfg;
	POS_UINT32 pageSize= 0;
	POS_UINT32 curPage=0;
	POS_UINT32 totalCnt,totalPage=0;
	POS_INT retVal = 0;
	POS_CHAR dstIpBuf[18] = {0};
	POS_CHAR gwBuf[18] = {0};
	POS_CHAR ipMaskBuf[18] = {0};
	struct in_addr saddr = {0};
	POS_UINT32 stCnt,endCnt,curCnt=0;

	pageSize = atoi(websGetVar(wp, "pageSize", "0"));
	if(pageSize==0)
	{
		pageSize= WEB_PAGESIZE_DEFAULT;
	}

	curPage = atoi(websGetVar(wp, "curPage", "0"));
	if(curPage==0)
	{
		curPage= WEB_CURRPAGE_DEFAULT;/*start from First-Page*/
	}

	/*Calc the offset*/
	stCnt= pageSize*(curPage-1)+1;
	endCnt= pageSize*curPage;

	/* Retrieve authorized onus */
	jsonData = cJSON_CreateObject();
	jsonArray = cJSON_AddArrayToObject(jsonData, "data");

	for (retVal = sllIpStaticRouteGetFirst(&ipRouteCfg);
		 M_SLL_OK == retVal;
		 retVal = sllIpStaticRouteGetNext(&ipRouteCfg) ) 
	{
		curCnt++;

		if(curCnt< stCnt)
			continue;

		if(curCnt > endCnt)
			break;

		jsonObj = cJSON_CreateObject();
		
		saddr.s_addr = ipRouteCfg.dstIpAddr;
		inet_ntoa_b(saddr, (char *)dstIpBuf);
		cJSON_AddStringToObject(jsonObj, "destIp",dstIpBuf);
		
		
		saddr.s_addr = ipRouteCfg.netMask;
		inet_ntoa_b(saddr, (char *)ipMaskBuf);
		cJSON_AddStringToObject(jsonObj, "destIpMask",ipMaskBuf);
		
		saddr.s_addr = ipRouteCfg.nextHopIp;
		inet_ntoa_b(saddr, (char *)gwBuf);
		cJSON_AddStringToObject(jsonObj, "gateWay",gwBuf);
		
		cJSON_AddItemToArray(jsonArray, jsonObj);
	}

    (void)sllIpStaticRouteCntGet(&totalCnt);
	cJSON_AddNumberToObject(jsonData, "total", totalCnt);

	/* Create a json data */
	jsonStr = cJSON_Print(jsonData);

	/* Send json string to client */
	websSetStatus(wp, WEB_RESPONSE_OK);
	websWriteHeaders(wp, -1, 0);
	websWriteHeader(wp, "Access-Control-Allow-Origin", "*");
	websWriteEndHeaders(wp);
	websWrite(wp, jsonStr);
	websDone(wp);

	if (POS_NULL != jsonStr) free(jsonStr);
	if (POS_NULL != jsonData) cJSON_Delete(jsonData);
	return;
}


static void createStaticRoute(Webs *wp)
{	   
	POS_UINT32 rc = 0;
	POS_UINT32 index = 0;
	POS_UINT32 vlan = 0;
	POS_CHAR stIpAddrBuff[18] = {0};
	POS_CHAR ipMaskBuff[18] = {0};
	POS_CHAR gwBuff[18] = {0};
	POS_UINT32 stIpAddr = 0;
	POS_UINT32 ipMask = 0;
	POS_UINT32 gw = 0;
	POS_INT retVal = 0;
	POS_INT responseCode = WEB_RESPONSE_OK;
	POS_INT32 l3Enable=0;
	const POS_CHAR *ret = OLT_CFG_RET_OK;

	/*L3 global enable or not*/
    sllL3IntfEnGet(&l3Enable);
	
    if(l3Enable == POS_FALSE)
    {
		responseCode  = WEB_RESPONSE_ERROR;
		ret = OLT_CFG_RET_l3_DIS;
		goto EXIT;
    }
	
	memcpy(stIpAddrBuff, (websGetVar(wp, "destIp", "0")), sizeof(stIpAddrBuff));
	memcpy(ipMaskBuff, (websGetVar(wp, "destIpMask", "0")), sizeof(ipMaskBuff));
	memcpy(gwBuff, (websGetVar(wp, "gateWay", "0")), sizeof(gwBuff));


    if (1 != inet_pton(AF_INET, stIpAddrBuff, (void*)&stIpAddr))
    {
		M_OLT_CFG_IPROUTE_FUN_RET_CHECK(M_SLL_COM_PARAM_ERROR, M_SLL_OK, responseCode, ret);	
    }

    if (1 != inet_pton(AF_INET, ipMaskBuff, (void*)&ipMask))
    {
		M_OLT_CFG_IPROUTE_FUN_RET_CHECK(M_SLL_COM_PARAM_ERROR, M_SLL_OK, responseCode, ret);	
    }
	
    if (1 != inet_pton(AF_INET, gwBuff, (void*)&gw))
    {
		M_OLT_CFG_IPROUTE_FUN_RET_CHECK(M_SLL_COM_PARAM_ERROR, M_SLL_OK, responseCode, ret);	
    }

	retVal = sllIpStaticRouteAdd( stIpAddr, ipMask,gw);
	printf("createStaticRoute stIpAddr 0x%x mask 0x%x gw 0x%x ,ret 0x%x\r\n",stIpAddr, ipMask,gw,retVal);
	if((M_SLL_L3_INTF_ERR_ROUTE_NEXTHOP_REACH != retVal)&&(M_SLL_OK != retVal))
	{
		M_OLT_CFG_IPROUTE_FUN_RET_CHECK(retVal, M_SLL_OK, responseCode, ret);
	}
	
	/* Send result to client */
EXIT:	websSetStatus(wp, responseCode);
	websWriteHeaders(wp, -1, 0);
	websWriteHeader(wp, "Access-Control-Allow-Origin", "*");
	websWriteEndHeaders(wp);
	websWrite(wp, ret);
	websDone(wp);
	return;
}



static void delIpRoute(Webs *wp)
{	   
	POS_UINT32 rc = 0;
	POS_UINT32 index = 0;
	POS_UINT32 vlan = 0;
	POS_CHAR stIpAddrBuff[18] = {0};
	POS_CHAR ipMaskBuff[18] = {0};
	POS_UINT32 stIpAddr = 0;
	POS_UINT32 ipMask = 0;
	POS_INT retVal = 0;
	POS_INT responseCode = WEB_RESPONSE_OK;
	const POS_CHAR *ret = OLT_CFG_RET_OK;
	
	memcpy(stIpAddrBuff, (websGetVar(wp, "destIp", "0")), sizeof(stIpAddrBuff));
	memcpy(ipMaskBuff, (websGetVar(wp, "destIpMask", "0")), sizeof(ipMaskBuff));

	if (1 != inet_pton(AF_INET, stIpAddrBuff, (void*)&stIpAddr))
	{
		M_OLT_CFG_IPROUTE_FUN_RET_CHECK(M_SLL_COM_PARAM_ERROR, M_SLL_OK, responseCode, ret);	
	}

	if (1 != inet_pton(AF_INET, ipMaskBuff, (void*)&ipMask))
	{
		M_OLT_CFG_IPROUTE_FUN_RET_CHECK(M_SLL_COM_PARAM_ERROR, M_SLL_OK, responseCode, ret);	
	}
	
	retVal = sllIpStaticRouteDel( stIpAddr, ipMask);
	printf("delIpRoute stIpAddr 0x%x mask 0x%x ,ret 0x%x\r\n",stIpAddr, ipMask,retVal);
	if((M_SLL_L3_INTF_ERR_ROUTE_NEXTHOP_REACH != retVal)&&(M_SLL_OK != retVal))
	{
		M_OLT_CFG_IPROUTE_FUN_RET_CHECK(retVal, M_SLL_OK, responseCode, ret);
	}
	
	M_OLT_CFG_IPROUTE_FUN_RET_CHECK(retVal, M_SLL_OK, responseCode, ret);
	
	/* Send result to client */
EXIT:	websSetStatus(wp, responseCode);
	websWriteHeaders(wp, -1, 0);
	websWriteHeader(wp, "Access-Control-Allow-Origin", "*");
	websWriteEndHeaders(wp);
	websWrite(wp, ret);
	websDone(wp);
	return;
}



int webOltConfig_ipRouteInit(void)
{
	websDefineAction("getStaticIpRouteTable", getStaticIpRouteTable);
	websDefineAction("createStaticRoute", createStaticRoute);
	websDefineAction("delIpRoute", delIpRoute);

}



