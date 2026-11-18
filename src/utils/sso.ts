import axios from 'axios'
import { config } from '@/config/axios/config'
import { getAccessToken } from '@/utils/auth'

/**
 * 统一登录（DaxPay 为登录入口、yudao 为账号匹配方）的前端会话探测。
 *
 * 背景：令牌不在前端手里，而在 ft-gateway 手里。
 *   · DaxPay 登录成功后下发 HttpOnly Cookie「Accesstoken」
 *   · 前端请求 /admin-api/** 时，网关取该 Cookie 调 DaxPay 校验身份
 *   · 网关把身份换成 yudao 令牌，注入 Authorization: Bearer <yudao token> 后转发
 *
 * 因此「有没有登录」这件事，前端不能靠 localStorage 里的 ACCESS_TOKEN 判断
 * （SSO 模式下它永远是空的），只能问一次接口：只要能拿到当前用户信息，
 * 就说明网关已经替我们把令牌换好了，即已登录。
 */

/**
 * 本次「页面加载」内是否已经确认过 SSO 有效。
 *
 * 刻意用内存变量而不是 sessionStorage：
 *   · sessionStorage 的标记会跟着标签页一直活下去，DaxPay 那边退出登录后
 *     用户按 F5 刷新，标记还在 → 守卫直接放行 → 页面停在原地，永远回不到登录页；
 *   · 换成内存变量后，刷新 = 模块重新求值 = 标记自然丢失，
 *     每次刷新都会重新探一次（探测很便宜，网关侧还有 1500 秒会话缓存），
 *     而 SPA 内部的路由跳转仍然共享这个标记，不会每次切菜单都打一次请求。
 */
let sessionMarked = false

/** 本地是否存在 yudao 令牌（原有账号密码登录路径） */
export const hasLocalToken = (): boolean => {
  return Boolean(getAccessToken())
}

/** 是否处于统一登录会话中（本次页面加载内已确认过） */
export const isSsoSessionMarked = (): boolean => {
  return sessionMarked
}

/** 清掉 SSO 标记：退出登录、网关返回 401 时调用 */
export const clearSsoSession = (): void => {
  sessionMarked = false
}

/** 探测的超时时间：网关换令牌要串两次 HTTP（DaxPay + yudao），不能掐太死 */
const PROBE_TIMEOUT = 6000

let probePromise: Promise<boolean> | undefined

/**
 * 探测统一登录会话是否有效。
 *
 * @returns true = 已登录（本地有令牌，或网关能换出令牌）
 */
export const hasSsoSession = (): Promise<boolean> => {
  if (hasLocalToken()) {
    return Promise.resolve(true)
  }
  if (sessionMarked) {
    return Promise.resolve(true)
  }
  // 并发路由跳转时共用同一次探测，避免重复请求
  if (!probePromise) {
    probePromise = probe()
      .then((valid) => {
        sessionMarked = valid
        return valid
      })
      .finally(() => {
        probePromise = undefined
      })
  }
  return probePromise
}

/**
 * 直接问一次「当前用户信息」。
 *
 * 注意：这里刻意用裸 axios，不走 @/config/axios 的 service ——
 * service 的响应拦截器在拿到 401 时会弹「登录状态已过期」的确认框，
 * 而探测失败是正常场景（比如根本没登录 DaxPay），不该打扰用户。
 */
const probe = async (): Promise<boolean> => {
  try {
    // 注意：这里【不发自定义请求头】。
    // 一旦带上 Cache-Control / Pragma 这类非简单请求头，浏览器会先发 OPTIONS 预检，
    // 预检一旦被网关拦掉，报的就是
    //   "Response to preflight request doesn't pass access control check"
    // 而探测本身不需要任何请求头，保持"简单请求"最稳。
    const res = await axios.get(`${config.base_url}/system/auth/get-permission-info`, {
      withCredentials: true,
      timeout: PROBE_TIMEOUT
    })
    const body = res.data || {}
    // yudao 成功返回 { code: 0, data: { user, roles, permissions, menus } }
    return body.code === 0 && !!body.data
  } catch {
    return false
  }
}
