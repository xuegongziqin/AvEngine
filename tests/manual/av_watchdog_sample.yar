/*
 * av_watchdog_sample.yar - 检出 tests\manual\av_watchdog_sample.cpp 编出的行为测试样本
 *
 * 这是给 AvEngine 做「YARA 引擎能不能命中测试样本」用的规则，默认**不**放进 rules\，
 * 需要时拷进去即可：
 *     copy tests\manual\av_watchdog_sample.yar rules\yara\
 * 之后 avengine.exe status 应显示规则数 +1，scan 该样本应输出 [YARA] 命中。
 * 不测了就把这个 .yar 从 rules\yara\ 删掉，避免长期开启（样本本身是明文标记，容易误报类似程序）。
 */

rule AVB_Watchdog_Sample
{
    meta:
        author      = "AvEngine test asset"
        description = "自复制到 %TEMP% + 双进程互守的行为测试样本（仅本地测试用）"
        reference   = "tests/manual/av_watchdog_sample.cpp"
        tlp         = "clear"

    strings:
        $marker = "AVB-WATCHDOG-SAMPLE" ascii wide
        $child  = "--child" ascii
        $exit   = "C:\\exit.exit" ascii wide
        $log    = ".log" ascii

    condition:
        uint16(0) == 0x5A4D and $marker and $child and $exit
}
