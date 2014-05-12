<%@ page import="tv.xiaocong.appstore.client.config.PartnerConfig" %>
<%@ page import="tv.xiaocong.appstore.client.security.MD5Util" %>
<%@ page import="tv.xiaocong.appstore.client.security.RSACoder" %>
<%

    //回调接口业务流程处理demo,如果测试使用自己生成sign的时候URLEncoder.encode

    //合作方自己对参数做一些非空判断

    //订单号
    String orderNo = request.getParameter("orderNo");
    //金额 精确到分
    String amount = request.getParameter("amount");
    // 小葱账号
    String account = request.getParameter("account");
    // 回调时间
    String notifyTime = request.getParameter("notifyTime");
    //商品描述
    String goodsDes = request.getParameter("goodsDes");
    //订单状态  1：成功；2：失败
    String status = request.getParameter("status");
    //签名
    String sign = request.getParameter("sign");
    //备注
    String mark = request.getParameter("mark");
    //签名类型
    String signType = request.getParameter("signType");


    //如果不传signType或者传入错误请按RSA解密
    if (signType != null && signType.equals("MD5")) {
        signType = "MD5";
    } else {
        signType = "RSA";
    }

    //签名算法
    String in = PartnerConfig.PARTNER_ID + "&" + PartnerConfig.PKG_NAME + "&" + amount + "&" + orderNo;

    Boolean isVerifyOk = Boolean.FALSE;
    String n_sign = "";
    if (signType.equals("MD5")) {
        //MD5验证
        n_sign = MD5Util.sign(in, PartnerConfig.MD5_KEY);
        if (n_sign.equals(sign)) {
            isVerifyOk = Boolean.TRUE;
        }
    } else {
        isVerifyOk = RSACoder.verify(in.getBytes(), PartnerConfig.XC_RSA_PUBLIC, sign);

    }

//    out.println(isVerifyOk+"</br>");
//    out.println(sign+"</br>");
//    out.println(in+"</br>");

    //.如果签名正确，则书写自己业务代码
    if (isVerifyOk) {
        Boolean isDeal = true;//写自己的业务代码
        if (isDeal) {
            out.println("success");
        } else {
            out.println("fail");
        }
    } else {
        //签名失败：sign_fail
        out.println("sign_fail");
    }


%>