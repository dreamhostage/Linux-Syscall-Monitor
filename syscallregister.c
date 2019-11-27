#include "Hook_module/hookModule.c"
#include "Hook_module/hook32bit.c"
unsigned int curLvl = 0;
bool isLogginEnable = false;
bool is32bitEnable = false;

void m_remove_hooks32_for_level(int lvl) {
    switch (curLvl) {
        case 1:
        {
            fh_32_remove_hooks(fh_32_level1, ARRAY_SIZE(fh_32_level1));
        }
            break;
        case 2:
        {
            fh_32_remove_hooks(fh_32_level1, ARRAY_SIZE(fh_32_level1));
            fh_32_remove_hooks(fh_32_level2, ARRAY_SIZE(fh_32_level2));
        }
            break;
        case 3:
        {
            fh_32_remove_hooks(fh_32_level1, ARRAY_SIZE(fh_32_level1));
            fh_32_remove_hooks(fh_32_level2, ARRAY_SIZE(fh_32_level2));
            fh_32_remove_hooks(fh_32_level3, ARRAY_SIZE(fh_32_level3));
        }
            break;
    }
}

void m_remove_hooks_for_level(int lvl) {
    switch (curLvl) {
        case 1:
        {
            fh_remove_hooks(level1, ARRAY_SIZE(level1));
        }
            break;
        case 2:
        {
            fh_remove_hooks(level1, ARRAY_SIZE(level1));
            fh_remove_hooks(level2, ARRAY_SIZE(level2));
        }
            break;
        case 3:
        {
            fh_remove_hooks(level1, ARRAY_SIZE(level1));
            fh_remove_hooks(level2, ARRAY_SIZE(level2));
            fh_remove_hooks(level3, ARRAY_SIZE(level3));
        }
            break;
    }
}

int m_set_hooks32_for_level(int lvl) {
    int err = 0;
    switch (lvl) {
        case 1:
        {
            err = fh_32_install_hooks(fh_32_level1, ARRAY_SIZE(fh_32_level1));
        }
            break;
        case 2:
        {
            err = fh_32_install_hooks(fh_32_level1, ARRAY_SIZE(fh_32_level1));
            err = fh_32_install_hooks(fh_32_level2, ARRAY_SIZE(fh_32_level2));
        }
            break;
        case 3:
        {
            err = fh_32_install_hooks(fh_32_level1, ARRAY_SIZE(fh_32_level1));
            err = fh_32_install_hooks(fh_32_level2, ARRAY_SIZE(fh_32_level2));
            err = fh_32_install_hooks(fh_32_level3, ARRAY_SIZE(fh_32_level3));
        }
            break;
    }
    return err;
}

int m_set_hooks_for_level(int lvl) {
    int err = 0;
    switch (lvl) {
        case 1:
        {
            err = fh_install_hooks(level1, ARRAY_SIZE(level1));
        }
            break;
        case 2:
        {
            err = fh_install_hooks(level1, ARRAY_SIZE(level1));
            err = fh_install_hooks(level2, ARRAY_SIZE(level2));
        }
            break;
        case 3:
        {
            err = fh_install_hooks(level1, ARRAY_SIZE(level1));
            err = fh_install_hooks(level2, ARRAY_SIZE(level2));
            err = fh_install_hooks(level3, ARRAY_SIZE(level3));
        }
            break;
    }
    return err;
}

static bool srg_set_log_level(int lvl) {
    if (lvl > 3 || lvl < 0) return false;
    if (isLogginEnable) m_remove_hooks_for_level(curLvl);
    if (is32bitEnable) m_remove_hooks32_for_level(curLvl);
    curLvl = 0;
    if ((!isLogginEnable)&&(!is32bitEnable)) {
        curLvl = lvl;
        return true;
    }
    bool result = 1;
    if (isLogginEnable)
        if (m_set_hooks_for_level(lvl) == 0) {
            curLvl = lvl;
            result = 1;
        } else
            result = 0;
    if (is32bitEnable)
        if (m_set_hooks32_for_level(lvl) == 0) {
            curLvl = lvl;
            result &= 1;
        } else
            result &= 0;
    return result;

}

static void srg_enable_logging(bool isEnable) {
    if (isEnable == isLogginEnable) return;
    isLogginEnable = isEnable;
    if (isEnable)
        m_set_hooks_for_level(curLvl);
    else
        m_remove_hooks_for_level(curLvl);
}

static void srg_enable_logging32bit(bool isEnable) {
    if (isEnable == is32bitEnable) return;
    is32bitEnable = isEnable;
    if (isEnable)
        m_set_hooks32_for_level(curLvl);
    else
        m_remove_hooks32_for_level(curLvl);
}
