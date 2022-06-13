
import datetime
import time
from uttils.logger import Logger
log=Logger()

def offset(count,offset_type, data=None, date_format="%Y-%m-%d %H:00:00"):
    """
    日期偏移（前N天、后N天）
    @param date_format: 格式（如：%Y-%m-%d %H:%M:%S）
    @param offset_type: 偏移类型（Q-向前偏移 即前N天，H-向后偏移 即后N天）
    @param count: 偏移天数
    @param data: 偏移基准日期（如：2020-11-14 19:48:51） 若为None则当前日期
    @return: 偏移后的日期
    """
    # 时间加减
    # 获取当前日期
    if data is None:
        data = datetime.datetime.now().strftime(date_format)
    today = datetime.datetime.strptime(data, date_format)

    # 计算偏移量
    log.info("sffset_type=={}".format(offset_type))
    if offset_type == 'Q':
        offset = datetime.timedelta(days=-count)
    elif offset_type == 'H':
        offset = datetime.timedelta(days=+count)
    else:
        log('偏移类型错误，预期：“Q”或“H”，实际：{}'.format(offset_type))
    # 获取修改后的时间并格式化

    re_date = (today + offset).strftime(date_format)
    return re_date


def TimeSerialize(timestamp):
    tmp = float(timestamp) / 1000
    dt = time.strftime('%Y-%m-%d %H:00:00', time.localtime(tmp))
    return dt


def Timesmap(data1):
    datas = {}
    hourly_data = {}
    dailys_data = {}
    # 先把数据写进字典
    hourly = data1.get('data').get('hourly')

    dailys = data1.get('data').get('daily')
    current_time = data1.get('data')['current']['ts']
    current_balance = data1.get('data')['current']['v']
    datas['reality_current_time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime((float(current_time)) / 1000))
    datas['current_time'] = TimeSerialize(current_time)
    datas['current_balance'] = current_balance



    for i in range(len(hourly)):
        timestamp = hourly[i].get('ts')
        hourly_data[str(TimeSerialize(timestamp))] = hourly[i].get('v')
    for j in range(len(dailys)):
        timestamp = dailys[j].get('ts')
        dailys_data[str(TimeSerialize(timestamp))] = dailys[j].get('v')
    # 将时间格式化后写入数组
    # datas['hourly_datas'] = hourly_data
    # datas['dailys_datas'] = dailys_data
    # 当前时间一天以前时间
    one_daybf = offset(count=1,offset_type='Q', data=datas.get('current_time'))
    log.info("计算后1天以前的时间为{}".format(one_daybf))

    # 当前时间一周以前时间
    one_wekbf = offset(count=7,offset_type='Q',  data=datas.get('current_time'))
    log.info("计算后1周以前的时间为{}".format(one_wekbf))

    # 当前时间一月以前时间
    one_mobf = offset(count=30, offset_type='Q', data=datas.get('current_time'))
    log.info("计算后1月以前的时间为{}".format(one_mobf))

    # 当前时间三月以前时间
    tre_mobf = offset(count=90,offset_type='Q',  data=datas.get('current_time'))
    log.info("计算后3月以前的时间为{}".format(tre_mobf))

    # 当前时间一年以前时间
    one_yebf = offset(count=365,offset_type='Q',  data=datas.get('current_time'))
    log.info("计算后1年以前的时间为{}".format(one_yebf))

    one_daybflist={}
    one_wekbflist={}
    one_mobflist={}
    tre_mobflist={}
    one_yebflist={}

    hourly_datas=hourly_data
    dailys_data=dailys_data
    log.info("所有的dailys数据{}".format(dailys_data))
    for key,value in hourly_datas.items():

        if key<=datas.get('current_time') and key>=one_daybf:
            one_daybflist[key]=value
        if key <= datas.get('current_time') and key >= one_wekbf:
            one_wekbflist[key] = value

    for key,value in dailys_data.items():

        if key<=datas.get('current_time') and key>=one_mobf:
            one_mobflist[key]=value
        if key <= datas.get('current_time') and key >= tre_mobf:
            tre_mobflist[key] = value
        if key <= datas.get('current_time') and key >= one_yebf:
            one_yebflist[key] = value
    #取出1天字典中的所有key
    one_daykeys=one_daybflist.keys()
    max_value=one_daybflist.get(max(one_daykeys))
    min_value=one_daybflist.get(min(one_daykeys))
    one_day_profit=(float(max_value)-float(min_value))/float(max_value)
    log.info("1天以内的所有数据{}".format(one_daybflist))
    log.info("1天以内的最近时间{}对应的资金{},最远时间{}对应的资产{},收益率{}".format(max(one_daykeys),max_value,min(one_daykeys),min_value,one_day_profit))
    one_daybflist['profit']=one_day_profit


    #取出1周字典中的所有key
    one_wekkeys=one_wekbflist.keys()
    max_value=one_wekbflist.get(max(one_wekkeys))
    min_value=one_wekbflist.get(min(one_wekkeys))
    one_wek_profit=(float(max_value)-float(min_value))/float(max_value)
    log.info("1周以内的所有数据{}".format(one_wekbflist))
    log.info("1周以内的最近时间{}对应的资金{},最远时间{}对应的资产{},收益率{}".format(max(one_wekkeys),max_value,min(one_wekkeys),min_value,one_day_profit))
    one_wekbflist['profit']=one_wek_profit

    #取出1月字典中的所有key
    one_mokeys=one_mobflist.keys()
    max_value=one_mobflist.get(max(one_mokeys))
    min_value=one_mobflist.get(min(one_mokeys))
    one_mo_profit=(float(max_value)-float(min_value))/float(max_value)
    log.info("1月以内的所有数据{}".format(one_mobflist))
    log.info("1月以内的最近时间{}对应的资金{},最远时间{}对应的资产{},收益率{}".format(max(one_mokeys),max_value,min(one_mokeys),min_value,one_mo_profit))
    one_mobflist['profit']=one_mo_profit


    #取出3月
    tre_mokeys=tre_mobflist.keys()
    max_value=tre_mobflist.get(max(tre_mokeys))
    min_value=tre_mobflist.get(min(tre_mokeys))
    tre_mo_profit=(float(max_value)-float(min_value))/float(max_value)
    log.info("3月以内的所有数据{}".format(tre_mobflist))
    log.info("3yue以内的最近时间{}对应的资金{},最远时间{}对应的资产{},收益率{}".format(max(tre_mokeys),max_value,min(tre_mokeys),min_value,tre_mo_profit))
    tre_mobflist['profit']=tre_mo_profit

    #取出1年
    one_year_keys=one_yebflist.keys()
    max_value=one_yebflist.get(max(one_year_keys))
    min_value=one_yebflist.get(min(one_year_keys))
    one_year_profit=(float(max_value)-float(min_value))/float(max_value)
    log.info("1年以内的所有数据{}".format(one_yebflist))
    log.info("1年以内的最近时间{}对应的资金{},最远时间{}对应的资产{},收益率{}".format(max(one_year_keys),max_value,min(one_year_keys),min_value,one_year_profit))
    one_yebflist['profit']=one_year_profit


    tre_mobflist['profit']=tre_mo_profit
    datas['one_daybflist']=one_daybflist
    datas['one_wekbflist']=one_wekbflist
    datas['one_mobflist']=one_mobflist
    datas['tre_mobflist']=tre_mobflist
    datas['one_yebflist']=one_yebflist

    return datas


def Overview(dictdata, t):
    time_local = time.localtime()
    pass


import json
from overview.overview_script import *

with open("request.txt", "r") as f:  # 打开文件
    data = f.read()  # 读取文件
data1=json.loads(data)
if __name__ == '__main__':
    res=Timesmap(data1)
    print(res)
