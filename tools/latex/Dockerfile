# Moi truong bien dich LaTeX cho hai ban bao cao (LNCS va IEEE), dung XeLaTeX.
# Build:  docker build -t nhom14-latex tools/latex
#
# Ghim image theo digest de ca nhom bien dich ra cung mot ket qua trong suot hoc ky.
# Khi TeX Live 2027 phat hanh (thuong vao thang 4), tlmgr cua ban 2026 khong cai duoc goi tu kho moi:
# luc do doi digest sang image moi hon.
FROM texlive/texlive:latest-medium@sha256:1e5ab8b60e1cc5cd5a0a37e406c0e04132435b9415c1620cde206da2d810eef9
# Goi ma lop llncs can nhung ban medium khong co (tlmgr phai tu cap nhat truoc)
RUN tlmgr update --self && tlmgr install aliascnt
