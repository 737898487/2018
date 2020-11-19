def Needleman_Wunsch_Merge(str1, str2):
    mis = -1  # mismatch
    mat = 3  # match
    gap = -3  # gap
    if len(str1) == 0 or len(str2) == 0:
        return 0, []

    m = len(str1)
    n = len(str2)
    lcs = [[i * gap] for i in range(0, m + 1)]
    lcs[0] = [j * gap for j in range(0, n + 1)]
    #
    for i in range(m):
        for j in range(n):
            lcs[i + 1].append(
                max(
                    lcs[i][j] + (mat if str1[i] == str2[j] else mis),
                    lcs[i][j + 1] + gap,
                    lcs[i + 1][j] + gap,
                )
            )
    # for i in lcs:
    #     print(i)

    i = m - 1
    j = n - 1
    # common_substr1 = u''
    # common_substr2 = u''
    # common_substr1 = u"%s%s" % (str1[i], common_substr1)
    # common_substr2 = u"%s%s" % (str2[j], common_substr2)

    common_substr1 = []
    common_substr2 = []
    common_substr1 = [str1[i]] + common_substr1
    common_substr2 = [str2[j]] + common_substr2

    try:
        while True:
            if i == 0 and j == 0:
                break
            if str1[i] == str2[j]:
                if (i > 0 and j > 0) and (lcs[i - 1][j - 1] + mat > lcs[i - 1][j] + (gap - mis) and lcs[i - 1][j - 1] + mat > lcs[i][j - 1] + (gap - mis)):
                    i = i - 1
                    j = j - 1
                    common_substr1 = [str1[i]] + common_substr1
                    common_substr2 = [str2[j]] + common_substr2
                    # common_substr1 = u"%s%s" % (str1[i], common_substr1)
                    # common_substr2 = u"%s%s" % (str2[j], common_substr2)

                else:
                    # if  lcs[i][j + 1] > lcs[i + 1][j] :
                    if (lcs[i][j + 1] > lcs[i + 1][j] or (i > j and lcs[i][j + 1] == lcs[i + 1][j])) and i != 0:
                        i = i - 1
                        common_substr1 = [str1[i]] + common_substr1
                        common_substr2 = [-1] + common_substr2
                        # common_substr1 = u"%s%s" % ('-', common_substr1)
                        # common_substr2 = u"%s%s" % ('-', common_substr2)

                    # else:
                    elif (lcs[i][j + 1] < lcs[i + 1][j] or (i <= j and lcs[i][j + 1] == lcs[i + 1][j])) and j != 0:
                        j = j - 1
                        # common_substr1 = u"%s%s" % ('-', common_substr1)
                        # common_substr2 = u"%s%s" % (str2[j], common_substr2)
                        common_substr1 = [-1] + common_substr1
                        common_substr2 = [str2[j]] + common_substr2

            else:
                if (i > 0 and j > 0) and (lcs[i - 1][j - 1] + mat > lcs[i - 1][j] + (gap - mis) and lcs[i - 1][j - 1] + mat > lcs[i][j - 1] + (gap - mis)):
                    i = i - 1
                    j = j - 1
                    common_substr1 = [str1[i]] + common_substr1
                    common_substr2 = [str2[j]] + common_substr2
                    # common_substr1 = u"%s%s" % (str1[i], common_substr1)
                    # common_substr2 = u"%s%s" % (str2[j], common_substr2)

                else:
                    # if lcs[i][j + 1] > lcs[i + 1][j]:
                    if (lcs[i][j + 1] > lcs[i + 1][j] or (i > j and lcs[i][j + 1] == lcs[i + 1][j])) and i != 0:
                        i = i - 1
                        common_substr1 = [str1[i]] + common_substr1
                        common_substr2 = [-1] + common_substr2
                        # common_substr1 = u"%s%s" % (str1[i], common_substr1)
                        # common_substr2 = u"%s%s" % ('-', common_substr2)
                    # else:
                    elif (lcs[i][j + 1] < lcs[i + 1][j] or (i <= j and lcs[i][j + 1] == lcs[i + 1][j])) and j != 0:
                        j = j - 1
                        common_substr1 = [-1] + common_substr1
                        common_substr2 = [str2[j]] + common_substr2
                        # common_substr1 = u"%s%s" % ('-', common_substr1)
                        # common_substr2 = u"%s%s" % (str2[j], common_substr2)
    except:
        print("Error!")
    # print(common_substr1)
    # print(common_substr2)
    # print(len(common_substr1))
    # print(len(common_substr2))

    match = 0
    gap = 0
    mismath = 0
    pattern = []
    # -1 space -2 different
    for n in range(len(common_substr1)):
        if common_substr1[n] == common_substr2[n]:
            match += 1
            pattern += [common_substr1[n]]
        elif common_substr1[n] == -1 or common_substr2[n] == -1:
            gap += 1
            pattern += [common_substr1[n]] if (common_substr2[n] == -1) else [common_substr2[n]]
        else:
            mismath += 1
            pattern += [[common_substr1[n], common_substr2[n]]]

    simi = round(float(match) / float(mismath + match + gap), 4)
    return simi, pattern