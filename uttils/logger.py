import logging

import datetime

import time

import os



# 日志保存本地的路径

log_path = "../logs"





class Logger:

    def __init__(self):

        # 文件的命名

        self.log_name = os.path.join(log_path, '%s.log' % time.strftime('%Y-%m-%d'))

        self.logger = logging.getLogger()

        self.logger.setLevel(logging.DEBUG)



        # 日志输出格式

        self.formatter = logging.Formatter('[%(asctime)s] - %(filename)s] - %(levelname)s: %(message)s')



    def __console(self, level, message):



        # 创建一个FileHandler，用于写到本地

        fh = logging.FileHandler(self.log_name, 'a', encoding='utf-8')

        fh.setLevel(logging.DEBUG)

        fh.setFormatter(self.formatter)

        self.logger.addHandler(fh)



        ch = logging.StreamHandler()  # 创建一个StreamHandler,用于输出到控制台

        ch.setLevel(logging.DEBUG)

        ch.setFormatter(self.formatter)

        self.logger.addHandler(ch)



        if level == 'info':

            self.logger.info(message)

        elif level == 'debug':

            self.logger.debug(message)

        elif level == 'warning':

            self.logger.warning(message)

        elif level == 'error':

            self.logger.error(message)



        # 这两行代码是为了避免日志输出重复问题

        self.logger.removeHandler(ch)

        self.logger.removeHandler(fh)



        # 关闭文件

        fh.close()



    def debug(self, message):

        self.__console('debug', message)



    def info(self, message):

        self.__console('info', message)



    def warning(self, message):

        self.__console('warning', message)



    def error(self, message):

        self.__console('error', message)





log = Logger()



if __name__ == "__main__":

    log = Logger()

    log.info("###### 测试开始 ######")

    log.info("{}".format(str(datetime.datetime.now())[:19]))

    log.warning("###### 测试结束 ######")

