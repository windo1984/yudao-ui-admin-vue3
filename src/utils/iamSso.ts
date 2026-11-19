import { iamLogin } from '@/api/login'
import { setTenantId, setToken } from '@/utils/auth'

/**
 * 统一认证（ft-iam ticket）免登引导。
 *
 * 基座 ft-layout 以 ft-iam 为唯一登录入口，打开本应用时在地址上挂一次性 ticket：
 *   · 这里读一次 ticket，向本应用后端 /system/auth/iam-login 换本应用自己的令牌
 *   · 换取成功后写入本地令牌缓存，后续请求按 yudao 原生方式带 Bearer
 *   · 立刻把 ticket 从地址栏抹掉（ticket 只能用一次，也不该留在书签/截图/Referer 里）
 *
 * 换取失败（ticket 过期/已被消费/本地没有对应账号）时不阻断启动，
 * 交给路由守卫按未登录处理，用户会看到本应用自己的登录页。
 */
export async function adoptIamTicketFromHost() {
  if (typeof window === 'undefined') {
    return
  }

  const url = new URL(window.location.href)
  const ticket = url.searchParams.get('ticket')
  if (!ticket) {
    return
  }

  url.searchParams.delete('ticket')
  window.history.replaceState(window.history.state, '', url.toString())

  try {
    // yudao 运营端固定使用默认租户（1）：tenant-id 头要在调用登录接口之前就生效，
    // 否则后端 TenantContextWebFilter 会直接 400「请求的租户标识未传递」
    setTenantId(1)
    const token = await iamLogin(ticket)
    if (!token?.accessToken) {
      console.warn('[yudao] 统一认证未返回令牌，退回本应用登录页')
      return
    }
    setToken(token)
    console.info('[yudao] 统一认证登录成功：', token.userId)
  } catch (error) {
    console.warn('[yudao] 统一认证 ticket 换取失败，退回本应用登录页', error)
  }
}
