### 简介

根据心动开放技术文档 [统一的Gateway](https://github.com/xindong/docs/blob/master/public/game_review/backend.md) 中的要求：
整体架构对公网暴露的IP控制在2-5个（可以自己开发网关，也可以使用负载均衡通用件例如HAProxy）。
因此需要游戏使用网关来与服务器后端进行通讯。

本项目提供一种通用方案，可以直接部署生产环境，也可以进行改造后部署。


