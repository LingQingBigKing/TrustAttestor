package com.lingqing.trustattestor.ui

import android.content.Context
import android.graphics.Typeface
import androidx.core.content.ContextCompat
import androidx.core.text.buildSpannedString
import androidx.core.text.color
import androidx.core.text.inSpans
import com.lingqing.trustattestor.R

object UserAgreement {

    private const val ACCEPTED_VERSION = "2026_02_10"
    private const val PREF_NAME = "trust_attestor_shared_data"
    private const val PREF_KEY_ACCEPTED = "user_agreement_accepted_$ACCEPTED_VERSION"

    fun hasAccepted(context: Context): Boolean {
        return context.applicationContext
            .getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
            .getBoolean(PREF_KEY_ACCEPTED, false)
    }

    fun markAccepted(context: Context) {
        context.applicationContext
            .getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(PREF_KEY_ACCEPTED, true)
            .apply()
    }

    fun updatedAt(context: Context): String = context.getString(R.string.agreement_updated_at)

    fun buildContent(context: Context) = buildSpannedString {
        val headingColor = ContextCompat.getColor(context, R.color.ta_text)
        val bodyColor = ContextCompat.getColor(context, R.color.ta_text_secondary)
        val metaColor = ContextCompat.getColor(context, R.color.ta_subtext)
        val english = context.resources.configuration.locales[0].language.equals("en", true)
        val lines = (if (english) USER_AGREEMENT_EN else USER_AGREEMENT_ZH).trim().lines()
        lines.forEach { raw ->
            val line = raw.trimEnd()
            when {
                line.isBlank() -> append("\n")
                line.startsWith("第") && line.contains("【") ||
                    line.startsWith("Article ") -> {
                    color(headingColor) {
                        inSpans(
                            android.text.style.StyleSpan(Typeface.BOLD),
                            android.text.style.RelativeSizeSpan(1.06f)
                        ) {
                            append(line)
                        }
                    }
                    append("\n")
                }

                line.startsWith("开发者联系方式") || line.startsWith("更新日期") ||
                    line.startsWith("Developer contact") || line.startsWith("Last updated") -> {
                    color(metaColor) {
                        inSpans(android.text.style.StyleSpan(Typeface.BOLD)) {
                            append(line)
                        }
                    }
                    append("\n")
                }

                else -> {
                    color(bodyColor) { append(line) }
                    append("\n")
                }
            }
        }
    }

    private const val USER_AGREEMENT_ZH = """
欢迎使用 TrustAttestor（以下简称“本程序”）。本协议是您与开发者凌卿就本程序的下载、安装、使用及相关功能所订立的协议。请您在使用前仔细阅读并充分理解本协议全部内容；您一旦安装、启动、使用本程序，或以其他方式接受本协议，即表示您已阅读、理解并同意受本协议约束。

第一条【服务定位与功能说明】
1. 本程序是一款面向 Android 设备的设备完整性与环境检测工具，主要用于对设备基础信息、系统环境、BootLoader 状态、TEE / Key Attestation 相关信息、Root / Hook 痕迹及其他与可信度评估相关的内容进行本地检测、整理与展示。
2. 本程序提供的是技术性辅助判断结果，旨在帮助用户进行环境识别、开发调试、设备排查与风险参考，不构成对设备绝对安全、官方认证状态、交易结论、合规结论或法律结论的承诺与保证。
3. 由于不同品牌机型、ROM、内核、权限策略、系统更新、第三方框架、网络状态及用户环境差异，检测结果可能出现误报、漏报、延迟、兼容性差异或部分检测项不可用的情况。

第二条【用户使用规则】
1. 您承诺仅将本程序用于合法、正当且合理的用途，不得将本程序用于攻击、入侵、破坏、规避安全机制、非法取证、非法控制设备、批量探测、破解或其他违反法律法规、公序良俗及他人合法权益的行为。
2. 未经开发者事先书面许可，您不得对本程序进行反编译、反汇编、逆向工程、修改、二次打包、镜像分发、出租、出借、出售、再许可，或以其他方式实施超出法律允许范围的使用行为。
3. 未经授权，您不得将本程序或其检测能力用于商业集成、对外收费服务、自动化平台、企业风控产品或其他商业场景；法律法规另有规定或双方另有书面约定的除外。

第三条【数据与隐私说明】
1. 为实现检测功能，本程序可能在设备本地读取并处理必要的设备基础信息、系统版本信息、内核信息、系统属性、证书链与 Attestation 相关数据、检测结果、诊断文本及其他与当前检测流程直接相关的信息。
2. 除您主动触发需要联网的功能外，当前版本的大部分检测逻辑在本地完成。本程序不会仅因您启动应用而主动将检测结果上传至开发者自建服务器。
3. 当您主动执行“获取最新证书吊销列表”等联网功能时，本程序可能访问 Google 官方接口以获取公开的 attestation status 数据，并将其保存在应用私有目录中，供后续本地检测使用。
4. 您理解并同意，在进行上述网络访问时，相关网络服务提供方、网络运营商或基础网络设施可能基于互联网通信原理处理连接所必需的网络元数据，例如 IP 地址、连接时间、请求路由等；该等处理行为由相应服务提供方依据其规则实施。
5. 本程序生成或缓存的检测结果、配置数据、更新时间信息及相关文件，可能存储于您的设备应用私有目录中，用于功能实现、结果展示或下次启动时恢复状态。
6. 除非获得您的明确授权、为履行法定义务、为响应有权机关依法提出的要求、为维护系统与用户安全所必需，或为处理您主动发起的服务请求，开发者不会主动向无关第三方共享您的检测数据。
7. 如您对隐私或敏感信息保护有更高要求，建议您在断网环境下使用本程序，或谨慎触发需要联网的相关功能。

第四条【权限、兼容性与安全边界】
1. 本程序仅在实现当前功能所必需的范围内使用系统能力与已声明权限。因 Android 系统限制、厂商策略、SELinux 策略、系统接口变化或硬件差异，部分能力可能无法在所有设备上保持一致。
2. 对于因系统限制、厂商定制、Root、解锁、调试环境、第三方模块、Hook 框架、虚拟化环境、系统裁剪或异常网络环境导致的功能异常、结果偏差、闪退、冻结或不可用，开发者将尽力改进，但不保证全部场景均可兼容。
3. 本程序不会因其存在而当然提升设备安全等级，也不能替代系统官方安全机制、厂商售后检测、司法鉴定、企业合规审计或其他专业服务。

第五条【免责声明】
1. 本程序按“现状”和“可用”状态提供。法律法规另有强制性规定的除外，开发者不对本程序的连续性、稳定性、无错误性、无中断性、适配性、准确性、完整性、及时性或特定用途适用性作出明示或默示保证。
2. 本程序提供的检测结果、提示信息、风险标签、异常统计及说明文本仅供参考，不应被视为您进行交易、维保、质保、售后维权、风控审核、设备认证、合规判断、司法取证或其他重要决策的唯一依据。
3. 您因依赖本程序结果、误解检测含义、在特殊环境中运行本程序，或因网络、系统、设备、第三方服务等原因导致的任何直接损失、间接损失、附带损失、后续损失、利润损失、数据损失或商誉损失，开发者在法律允许的范围内不承担责任。
4. 如因您违反本协议、滥用本程序或实施违法违规行为，导致任何第三方主张权利、提出索赔、行政调查或诉讼仲裁的，您应自行承担全部责任，并保证开发者免受因此遭受的损失。

第六条【知识产权】
1. 本程序及其相关文本、界面设计、图形图像、标识、代码、文档及其他组成部分的知识产权，依法归开发者凌卿或相关权利人所有，并受著作权法、商标法、反不正当竞争法及其他适用法律法规保护。
2. 未经权利人书面许可，任何个人或组织不得擅自复制、传播、展示、修改、改编、反向提取、镜像部署或以其他方式使用本程序的全部或部分内容。

第七条【协议更新、变更与终止】
1. 开发者有权根据产品迭代、法律法规变化、功能调整或运营需要，对本协议内容进行更新或变更。更新后的协议可通过应用内页面、发布说明、官方网站或其他合理方式进行公示。
2. 如您在协议更新后继续安装、启动或使用本程序，即视为您已接受更新后的协议；如您不同意更新内容，您应立即停止使用并卸载本程序。
3. 开发者有权在法律允许范围内，根据实际情况中止、限制或终止本程序的全部或部分功能，而无须就此向您承担赔偿责任。

第八条【法律适用与争议解决】
1. 本协议的订立、效力、解释、履行、变更、终止及争议解决，均适用中华人民共和国法律；法律另有强制性规定的，从其规定。
2. 因本协议或本程序的使用所引起的任何争议，双方应优先通过友好协商解决；协商不成的，任何一方可向开发者所在地有管辖权的人民法院提起诉讼。

第九条【其他条款】
1. 本协议任何条款被认定为无效、违法或不可执行的，不影响其余条款的效力；其余条款仍应继续有效并对双方具有约束力。
2. 本协议标题仅为阅读便利而设，不影响条款含义的解释。
3. 在法律允许的范围内，本协议的解释权归开发者所有。

开发者联系方式：ling_qing_lq@163.com
更新日期：2026年2月10日
"""

    private const val USER_AGREEMENT_EN = """
Welcome to TrustAttestor (the “Application”). This agreement is between you and the developer, LingQing, and governs the download, installation, and use of the Application and its related features. Read and understand the entire agreement before use. By installing, launching, or using the Application, or otherwise accepting this agreement, you confirm that you have read, understood, and agree to be bound by it.

Article 1 — Service purpose and features
1. The Application is an Android device-integrity and environment diagnostic tool. It locally collects, evaluates, and presents device baseline data, system environment information, Bootloader state, TEE and Key Attestation data, Root or hook traces, and other signals relevant to trust assessment.
2. Results are technical decision-support information intended for environment identification, development, debugging, device troubleshooting, and risk reference. They are not a promise or guarantee of absolute device security, official certification, transaction outcome, compliance, or legal conclusion.
3. Differences in device models, ROMs, kernels, permission policies, system updates, third-party frameworks, networks, and user environments may cause false positives, false negatives, delays, compatibility differences, or unavailable checks.

Article 2 — Acceptable use
1. You may use the Application only for lawful, legitimate, and reasonable purposes. You must not use it to attack, intrude upon, damage, or bypass security mechanisms; perform unlawful forensics; unlawfully control devices; conduct bulk probing; crack systems; or otherwise violate applicable law, public order, or the rights of others.
2. Unless applicable law permits it or the developer gives prior written permission, you must not decompile, disassemble, reverse engineer, modify, repackage, mirror, distribute, rent, lend, sell, sublicense, or otherwise use the Application beyond the permitted scope.
3. Without authorization, you must not integrate the Application or its detection capabilities into paid services, automation platforms, enterprise risk products, or other commercial scenarios, unless required by law or separately agreed in writing.

Article 3 — Data and privacy
1. To perform diagnostics, the Application may locally read and process necessary device information, system and kernel versions, system properties, certificate chains, Attestation data, diagnostic results, and other data directly relevant to the current scan.
2. Most checks in the current version run locally. Except when you enable or trigger an online feature, merely launching the Application does not upload diagnostic results to the developer’s server.
3. When you enable cloud attestation or manually update the certificate revocation list, the Application may connect to the configured TrustAttestor service or Google’s official attestation-status service and process the data needed for that request.
4. Network providers and infrastructure may process connection metadata required for Internet communication, including IP address, time, and routing information, under their own terms.
5. Results, settings, update timestamps, and related files may be stored in the Application’s private device storage for operation, display, or restoration on the next launch.
6. The developer does not actively share your diagnostic data with unrelated third parties without explicit authorization, except where legally required, requested by a competent authority, necessary to protect systems and users, or needed to fulfil a request you initiated.
7. If you require stronger privacy protection, use the Application offline and enable network features only after reviewing their purpose.

Article 4 — Permissions, compatibility, and security boundaries
1. The Application uses declared permissions and system capabilities only as needed for its current functions. Android restrictions, vendor policies, SELinux policy, API changes, and hardware differences may make some capabilities inconsistent or unavailable.
2. Root access, unlocked devices, debugging, third-party modules, hook frameworks, virtualization, customized systems, or abnormal networks may cause incorrect results, crashes, freezes, or unavailable features. The developer may improve compatibility but cannot guarantee every environment.
3. The Application does not by itself increase a device’s security level and does not replace official platform security, vendor service diagnostics, forensic examination, compliance audits, or other professional services.

Article 5 — Disclaimer
1. The Application is provided “as is” and “as available.” Except where mandatory law requires otherwise, no express or implied warranty is made regarding continuity, stability, error-free operation, uninterrupted availability, compatibility, accuracy, completeness, timeliness, or fitness for a particular purpose.
2. Diagnostic results, notices, risk labels, anomaly counts, and explanations are for reference only and must not be the sole basis for transactions, warranty decisions, after-sales claims, risk approval, certification, compliance decisions, forensics, or other important decisions.
3. To the extent permitted by law, the developer is not liable for direct, indirect, incidental, consequential, profit, data, or reputation losses caused by reliance on results, misunderstanding of diagnostics, unusual environments, networks, devices, systems, or third-party services.
4. You are responsible for claims, investigations, litigation, or losses caused by your breach of this agreement, misuse of the Application, or unlawful conduct.

Article 6 — Intellectual property
1. Intellectual-property rights in the Application, its text, interface design, graphics, marks, code, documentation, and other components belong to LingQing or the relevant rights holders and are protected by applicable law.
2. No person or organization may reproduce, distribute, display, modify, adapt, extract, mirror, deploy, or otherwise use all or part of the Application without written permission from the rights holder, except where the law expressly permits it.

Article 7 — Updates, changes, and termination
1. The developer may update this agreement as the product, law, functions, or operational needs change. Updated terms may be published in the Application, release notes, an official website, or another reasonable channel.
2. Continued installation, launch, or use after an update constitutes acceptance of the updated terms. If you disagree, stop using and uninstall the Application.
3. To the extent permitted by law, the developer may suspend, limit, or terminate all or part of the Application without liability for compensation.

Article 8 — Governing law and disputes
1. The formation, validity, interpretation, performance, amendment, termination, and dispute resolution of this agreement are governed by the laws of the People’s Republic of China, subject to mandatory legal provisions.
2. Disputes should first be resolved through good-faith consultation. If consultation fails, either party may bring proceedings before a court with jurisdiction at the developer’s location.

Article 9 — Other terms
1. If any term is found invalid, unlawful, or unenforceable, the remaining terms remain effective and binding.
2. Headings are for convenience only and do not affect interpretation.
3. To the extent permitted by law, the developer retains the right to interpret this agreement.

Developer contact: ling_qing_lq@163.com
Last updated: February 10, 2026
"""
}
