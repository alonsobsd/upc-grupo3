library("xml2")
library("methods")
library("rvest")
library("dplyr")
library("jsonlite")
library("ggplot2")
library("stringr")
library("reactable")

#
# Carga o extrae los datos desde los resultados de OpenVAS
#

if(file.exists("dataframes/nvt.rds")) {
  nvt.final <- readRDS("dataframes/nvt.rds")
} else {
  openvas.files <- list.files(path = "resultados/", pattern = ".xml")
  
  nvt.final <- data.frame()
  
  for(archivo in openvas.files) {
    print("Procesando archivo : ")
    print(archivo)
    
    openvas.src <- xml2::read_xml(x = paste("resultaodos/" ,archivo, sep = ""))
    openvas.res <- xml2::xml_find_all(openvas.src, "//report/results/result")
    
    id <- as.character(xml2::xml_attrs(openvas.res, "id"))
    vuln <- as.character(xml2::xml_text(xml2::xml_find_all(openvas.res,"//report/results/result/name")))
    score <- as.numeric(xml2::xml_text(xml2::xml_find_all(openvas.res,"//report/results/result/nvt/cvss_base")))
    cve <- sapply(openvas.res,
                  function(x)
                    paste(rvest::html_text(rvest::html_elements(x, xpath = "nvt/refs/ref[@type='cve']/@id")), collapse = ",")
    )  
    
    nvt.tabla <- data.frame(id, score, vuln, cve)
    nvt.dataframe <- tidyr::separate_rows(nvt.tabla, cve, convert = TRUE, sep = ",")  
    
    nvt.final <- dplyr::bind_rows(nvt.final, nvt.dataframe)
  }
  
  #colnames(nvt.final) =c("id","score","vuln","cve")
  
  saveRDS(nvt.final, file = "dataframes/nvt.rds")
}

#
# Carga o extrae de datos desde los archivos nvdcve
#

if(file.exists("dataframes/cve.rds")) {
  cve.final <- readRDS("dataframes/cve.rds")
} else {
  cve.files <- list.files(path = "fuentes/CVE",pattern = ".json")
  
  cve.final <- data.frame()
  
  for(archivo in cve.files) {
    cve.src <- fromJSON(paste("fuentes/CVE/",archivo, sep = ""))
    
    cve <- cve.src$CVE_Items$cve$CVE_data_meta$ID
    cvssV2 <- cve.src$CVE_Items$impact$baseMetricV2$cvssV2$baseScore
    cvssV3 <- cve.src$CVE_Items$impact$baseMetricV3$cvssV3$baseScore
    exploitV2 <- cve.src$CVE_Items$impact$baseMetricV2$exploitabilityScore
    exploitV3 <- cve.src$CVE_Items$impact$baseMetricV3$exploitabilityScore
    impactV2 <- cve.src$CVE_Items$impact$baseMetricV2$impactScore
    impactV3 <- cve.src$CVE_Items$impact$baseMetricV3$impactScore
    cwe.data <- cve.src$CVE_Items$cve$problemtype$problemtype_data
    
    cwe <- unlist(lapply( cwe.data , 
                          function(x)
                            paste(x[[1]][[1]]$value, collapse = ",") ))
    
    cve.tabla <- data.frame(cve, cvssV2, exploitV2, impactV2, cwe, stringsAsFactors = FALSE)
    cve.dataframe <- tidyr::separate_rows(cve.tabla, cwe , convert = TRUE, sep = ",")
    cve.final <- dplyr::bind_rows(cve.final, cve.dataframe)
  }
  
  #colnames(cve.final) =c("cve","cvssV2","exploitV2","impactV2","cwe")
  
  saveRDS(cve.final, file = "dataframes/cve.rds")
}

#
# Carga o extrae los datos desde el top CWE
#

if(file.exists("dataframes/cwetop.rds")) {
  cwetop.final <- readRDS("dataframes/cwetop.rds")
} else {
  cwetop.src <- read_html(x = "fuentes/CWE-Top-2020.xml")
  
  cwetop.res <- html_nodes(cwetop.src, "weakness")
  
  cwe <- paste("CWE-",html_attr(cwetop.res,'id'), sep = "")
  nombre <- html_attr(cwetop.res,'name')
  
  cwetop.final <- data.frame(cwe, nombre)
  
  saveRDS(cwetop.final, file = "dataframes/cwetop.rds")    
}

#
# Carga o extrae los datos desde el top OWASP
#

if(file.exists("dataframes/owastop.rds")) {
  owastop.final <- readRDS("dataframes/owastop.rds")
} else {
  owastop.src <- read_html(x = "fuentes/OWAS-Top-2020.xml")
  owastop.res <- html_nodes(owastop.src, "weakness")
  
  cwe <- paste("CWE-", html_attr(owastop.res,'id'), sep = "")
  nombre <- html_attr(owastop.res,'name')
  
  owastop.final <- data.frame(cwe, nombre)
  
  saveRDS(owastop.final, file = "dataframes/owastop.rds")      
}

#
# Suma de vulnerabilidades con y sin registro CVE
#

sicve <- nvt.final %>% filter(str_detect(cve, "CVE")) %>% count()
nocve <- nvt.final %>% filter(cve == "" | is.na(cve)) %>% count()

data <- data.frame("tipo" = c("Con CVE","Sin CVE"), "valor" = c(sicve$n, nocve$n))

bp <- ggplot(data, aes(x="",y=valor, fill=tipo)) + xlab("") +ylab("") + geom_bar(stat="identity", width = 1)
plot.pie <- bp + coord_polar("y", start = 0) + theme_minimal() + scale_fill_brewer(palette = "Blues") +
  geom_text(aes(label = valor))

#
# Suma por nivel de severidad
#

low.count <- nvt.final %>% select(id, score) %>% distinct(id, score) %>% filter(score <= 3.9) %>% summarise(contador = n())
medium.count <- nvt.final %>% select(id, score) %>% distinct(id, score) %>% filter(score > 3.9 & score <= 6.9) %>% summarise(contador = n())
high.count <- nvt.final %>% select(id, score) %>% distinct(id, score) %>% filter(score > 6.9 & score <= 10.0) %>% summarise(contador = n())

severidad_order <- c("Low","Medium","High")

data <- data.frame("Severidad" = c("Low","Medium","High"), "Valor" = c(low.count$contador, medium.count$contador, high.count$contador))

plot.severidad <- ggplot(data, aes(x= factor(Severidad, level=severidad_order), y = Valor, fill = Severidad ))+ geom_bar(width = 1, stat = "identity")+ labs(title = "Vulnerabilidades por nivel de severidad según OpenVAS", y = "Vulnerabilidades") + geom_text(aes(label=Valor)) + xlab("Severidad") + scale_fill_manual(values=c("#ff0000","#008000","#ffff00"))

#
# Vulnerabilidades que tienen un CVE pero no existen en NIST
#

cve.distinct <- cve.final %>% distinct(cve,cvssV2, exploitV2,impactV2)
nvt.distinct <- nvt.final %>% filter(str_detect(cve, "CVE"))

df1 <- merge(cve.distinct, nvt.distinct, by="cve", all.y = TRUE)
df2 <- merge(cve.distinct, nvt.final, by="cve")

nocve.diff <- setdiff(df1, df2) %>% select(cve,id,vuln)

#
# CVE que no cuentan con valores en las métricas de NIST
#

dfcomparativo <- merge(cve.distinct, nvt.final, by="cve")

noscore <- dfcomparativo %>% filter(is.na(cvssV2) & is.na(exploitV2) & is.na(impactV2))  %>% select(cve,id,vuln)

#
# Cuadro comparativo de las vulnerabilidades encontradas según sus métricas
#

low.cvss <- dfcomparativo %>% select(cvssV2) %>% filter(cvssV2 <= 3.9) %>% summarise(contador = n())
medium.cvss <- dfcomparativo %>% select(cvssV2) %>% filter(cvssV2 > 3.9 & cvssV2 <= 6.9) %>% summarise(contador = n())
high.cvss <- dfcomparativo %>% select(cvssV2) %>% filter(cvssV2 > 6.9 & cvssV2 <= 10.0) %>% summarise(contador = n())

low.exploit <- dfcomparativo %>% select(exploitV2) %>% filter(exploitV2 <= 3.9) %>% summarise(contador = n())
medium.exploit <- dfcomparativo %>% select(exploitV2) %>% filter(exploitV2 > 3.9 & exploitV2 <= 6.9) %>% summarise(contador = n())
high.exploit <- dfcomparativo %>% select(exploitV2) %>% filter(exploitV2 > 6.9 & exploitV2 <= 10.0) %>% summarise(contador = n())

low.impact <- dfcomparativo %>% select(impactV2) %>% filter(impactV2 <= 3.9) %>% summarise(contador = n())
medium.impact <- dfcomparativo %>% select(impactV2) %>% filter(impactV2 > 3.9 & impactV2 <= 6.9) %>% summarise(contador = n())
high.impact <- dfcomparativo %>% select(impactV2) %>% filter(impactV2 > 6.9 & impactV2 <= 10.0) %>% summarise(contador = n())

multi <- as.matrix(data.frame(Severidad = c(low.cvss$contador, medium.cvss$contador, high.cvss$contador),
                              Explotabilidad = c(low.exploit$contador, medium.exploit$contador, high.exploit$contador),
                              Impacto = c(low.impact$contador, medium.impact$contador, high.impact$contador)                               
))

rownames(multi) <- c("Low","Medium","High")

plot.comparativo <- barplot(multi, xlab = "Tipo de análisis", ylab = "Nro. vulnerabilidades", main = "Vulnerabilidades x métrica",
                            col = c("#008000","#ffff00","#ff0000"),
                            legend.text = rownames(multi), 
                            args.legend = list(x="right"))

#
# Relación de vulnerabilidades que deberán ser atendidas como prioridad
#

highscore <- dfcomparativo %>% filter(cvssV2 > 6.9 & exploitV2 > 6.9 & impactV2 > 6.9) %>% select(id, vuln, cve, cvssV2, exploitV2, impactV2) %>% arrange(desc(cvssV2, exploitV2, impactV2), .by_group = TRUE )

#
# Cuadro de vulnerabilidades encontradas que están dentro del CWE Top List
#

dfcwe <- merge(cve.final, nvt.final, by="cve")

cwe.merge1 <- dfcwe %>% inner_join(cwetop.final, by="cwe") %>% select(cwe, nombre) %>% group_by(cwe, nombre) %>% count(cwe)

cwe.legend1 <- cwe.merge1[order(cwe.merge1$n, cwe.merge1$nombre, decreasing = TRUE), ] %>% select(cwe, nombre)

plot.cwetop <- ggplot(cwe.merge1) +
  aes(x = cwe, fill = nombre, weight = n) +
  scale_x_discrete(limits = cwe.merge1$cwe[order(cwe.merge1$n, cwe.merge1$nombre)]) + 
  scale_fill_hue(limits = cwe.merge1$nombre[order(cwe.merge1$n, cwe.merge1$nombre)], l = 40, c = 65) +    
  geom_bar() +
  geom_text(aes(y = n, label = n, hjust = -0.3))+
  coord_flip() +
  labs(
    x = "CWE Top List",
    y = "Vulnerabilidades",
    title = "Vulnerabilidades en Top CWE",
    fill = "CWE"
  ) +
  theme_classic() +
  theme(
    legend.position = "",
    plot.title = element_text(
      size = 25L,
      face = "bold",
      hjust = 0.5
    ),
    axis.title.y = element_text(
      size = 15L,
      face = "bold"
    ),
    axis.title.x = element_text(
      size = 15L,
      face = "bold"
    )
  ) + guides(fill = guide_legend(nrow = 20, byrow = TRUE))

#
# Cuadro de vulnerabilidades encontradas que están dentro del OWAS Top List
#

cwe.merge2 <- dfcwe %>% inner_join(owastop.final, by="cwe") %>% select(cwe, nombre) %>% group_by(cwe, nombre) %>% count(cwe)

cwe.legend2 <- cwe.merge2[order(cwe.merge2$n, cwe.merge2$nombre, decreasing = TRUE), ] %>% select(cwe, nombre)

plot.owastop <- ggplot(cwe.merge2) +
  aes(x = cwe, fill = nombre, weight = n) +
  scale_x_discrete(limits = cwe.merge2$cwe[order(-cwe.merge2$n, decreasing = TRUE)]) +
  scale_fill_hue(limits = cwe.merge2$nombre[order(-cwe.merge2$n, decreasing = FALSE)], l = 40, c = 65 ) +  
  geom_bar() +
  geom_text(aes(y = n, label = n, hjust = -0.3))+  
  coord_flip() +  
  labs(
    x = "OWAS Top List",
    y = "Vulnerabilidades",
    title = "Vulnerabilidades en Top OWAS",
    fill = "CWE"
  ) +
  theme_classic() +
  theme(
    legend.position = "",
    plot.title = element_text(
      size = 25L,
      face = "bold",
      hjust = 0.5
    ),
    axis.title.y = element_text(
      size = 15L,
      face = "bold"
    ),
    axis.title.x = element_text(
      size = 15L,
      face = "bold"
    )
  )

